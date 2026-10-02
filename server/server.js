const express=require('express');
const path=require('path'),fs=require('fs'),crypto=require('crypto'),bcrypt=require('bcryptjs'),Database=require('better-sqlite3');
const helmet=require('helmet'),rateLimit=require('express-rate-limit'),cookieParser=require('cookie-parser');

const app=express();
const PORT=Number(process.env.PORT||3000),HOST=process.env.HOST||'127.0.0.1';
const DAYS=Number(process.env.SESSION_DAYS||14),SITE=process.env.SITE_NAME||'Community Forum';
fs.mkdirSync(path.join(__dirname,'../data'),{recursive:true});
const db=new Database(path.join(__dirname,'../data/forum.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,display_name TEXT NOT NULL, password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',banned INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS forums(id INTEGER PRIMARY KEY,name TEXT UNIQUE NOT NULL,description TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS threads(id INTEGER PRIMARY KEY,forum_id INTEGER NOT NULL,user_id INTEGER NOT NULL,title TEXT NOT NULL,locked INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY,thread_id INTEGER NOT NULL,user_id INTEGER NOT NULL,body TEXT NOT NULL,edited INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY,post_id INTEGER NOT NULL,user_id INTEGER NOT NULL,reason TEXT NOT NULL,created_at TEXT NOT NULL,resolved INTEGER NOT NULL DEFAULT 0);
`);
const now=()=>new Date().toISOString(), hash=t=>crypto.createHash('sha256').update(t).digest('hex');
if(!db.prepare('SELECT id FROM forums LIMIT 1').get()){
 const add=db.prepare('INSERT INTO forums(name,description,created_at) VALUES(?,?,?)');
 add.run('General Discussion','Talk about anything that fits the community.',now());
 add.run('Technology','Programming, Linux, hardware and technology.',now());
 add.run('Support','Questions, troubleshooting and help.',now());
}
const adminUser=process.env.ADMIN_USERNAME,adminPass=process.env.ADMIN_PASSWORD;
if(adminUser&&adminPass&&!db.prepare('SELECT id FROM users WHERE username=?').get(adminUser)){
 db.prepare('INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES(?,?,?,?,?)').run(adminUser,adminUser,bcrypt.hashSync(adminPass,12),'admin',now());
 console.log('Created configured admin:',adminUser);
}
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false,crossOriginEmbedderPolicy:false}));
app.use(cookieParser());
app.use(express.json({limit:'64kb'}));
app.use(express.urlencoded({extended:false,limit:'32kb'}));
app.use(rateLimit({windowMs:15*60*1000,limit:300,standardHeaders:'draft-8',legacyHeaders:false}));
app.use((req,res,next)=>{res.setHeader('Cache-Control','no-store');next()});

function setSession(res,userId){const token=crypto.randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hash(token),userId,Date.now()+DAYS*86400000);res.cookie('sid',token,{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:DAYS*86400000,path:'/'});}
function userFrom(req){const token=req.headers.cookie?.match(/(?:^|; )sid=([^;]+)/)?.[1];if(!token)return null;const s=db.prepare('SELECT s.user_id,u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(hash(decodeURIComponent(token)),Date.now());return s?.banned?null:s||null}
function auth(req,res,next){req.user=userFrom(req);if(!req.user)return res.status(401).json({error:'Authentication required'});next()}
function admin(req,res,next){auth(req,res,()=>req.user.role==='admin'?next():res.status(403).json({error:'Admin access required'}))}
function cleanUser(u){return u&&{id:u.id,username:u.username,display_name:u.display_name,role:u.role,created_at:u.created_at}}
function validUsername(s){return typeof s==='string'&&/^[a-zA-Z0-9_]{3,24}$/.test(s)}
function validBody(s,max=10000){return typeof s==='string'&&s.trim().length>0&&s.length<=max}

app.post('/api/auth/register',rateLimit({windowMs:60*60*1000,limit:10}),async(req,res)=>{
 const {username,password,display_name}=req.body;
 if(!validUsername(username)||typeof password!=='string'||password.length<10||password.length>200)return res.status(400).json({error:'Username or password does not meet requirements'});
 if(db.prepare('SELECT id FROM users WHERE username=?').get(username))return res.status(409).json({error:'Username already exists'});
 const name=(display_name||username).trim().slice(0,40)||username;
 const info=db.prepare('INSERT INTO users(username,display_name,password_hash,created_at) VALUES(?,?,?,?)').run(username,name,await bcrypt.hash(password,12),now());
 setSession(res,info.lastInsertRowid);res.json({user:cleanUser(db.prepare('SELECT * FROM users WHERE id=?').get(info.lastInsertRowid))});
});
app.post('/api/auth/login',rateLimit({windowMs:15*60*1000,limit:15}),async(req,res)=>{
 const u=db.prepare('SELECT * FROM users WHERE username=?').get(req.body.username||'');
 if(!u||u.banned||!(await bcrypt.compare(req.body.password||'',u.password_hash)))return res.status(401).json({error:'Invalid username or password'});
 setSession(res,u.id);res.json({user:cleanUser(u)});
});
app.post('/api/auth/logout',(req,res)=>{const t=req.headers.cookie?.match(/(?:^|; )sid=([^;]+)/)?.[1];if(t)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash(decodeURIComponent(t)));res.clearCookie('sid',{path:'/'});res.json({ok:true})});
app.get('/api/auth/me',(req,res)=>res.json({user:cleanUser(userFrom(req))}));

app.get('/api/forums',(req,res)=>res.json({forums:db.prepare(`SELECT f.*,COUNT(t.id) thread_count FROM forums f LEFT JOIN threads t ON t.forum_id=f.id GROUP BY f.id ORDER BY f.id`).all()}));
app.get('/api/forums/:id/threads',(req,res)=>{
 const forum=db.prepare('SELECT * FROM forums WHERE id=?').get(Number(req.params.id));if(!forum)return res.status(404).json({error:'Forum not found'});
 const threads=db.prepare(`SELECT t.*,u.username,u.display_name,(SELECT COUNT(*)-1 FROM posts p WHERE p.thread_id=t.id) reply_count FROM threads t JOIN users u ON u.id=t.user_id WHERE t.forum_id=? ORDER BY t.updated_at DESC`).all(forum.id);
 res.json({forum,threads});
});
app.post('/api/forums/:id/threads',auth,(req,res)=>{
 if(!validBody(req.body.title,160)||!validBody(req.body.body))return res.status(400).json({error:'Title and body are required'});
 const forum=db.prepare('SELECT id FROM forums WHERE id=?').get(Number(req.params.id));if(!forum)return res.status(404).json({error:'Forum not found'});
 const t=now(),tx=db.transaction(()=>{const x=db.prepare('INSERT INTO threads(forum_id,user_id,title,created_at,updated_at) VALUES(?,?,?,?,?)').run(forum.id,req.user.id,req.body.title.trim(),t,t);db.prepare('INSERT INTO posts(thread_id,user_id,body,created_at,updated_at) VALUES(?,?,?,?,?)').run(x.lastInsertRowid,req.user.id,req.body.body.trim(),t,t);return x.lastInsertRowid});res.json({id:tx});
});
app.get('/api/threads/:id',(req,res)=>{
 const thread=db.prepare(`SELECT t.*,f.name forum_name FROM threads t JOIN forums f ON f.id=t.forum_id WHERE t.id=?`).get(Number(req.params.id));if(!thread)return res.status(404).json({error:'Thread not found'});
 const posts=db.prepare('SELECT p.*,u.username,u.display_name,u.role FROM posts p JOIN users u ON u.id=p.user_id WHERE p.thread_id=? ORDER BY p.id').all(thread.id);res.json({thread,posts,user:cleanUser(userFrom(req))});
});
app.post('/api/threads/:id/posts',auth,(req,res)=>{
 const thread=db.prepare('SELECT * FROM threads WHERE id=?').get(Number(req.params.id));if(!thread)return res.status(404).json({error:'Thread not found'});if(thread.locked)return res.status(423).json({error:'Thread is locked'});if(!validBody(req.body.body))return res.status(400).json({error:'Post body is required'});
 const t=now(),x=db.prepare('INSERT INTO posts(thread_id,user_id,body,created_at,updated_at) VALUES(?,?,?,?,?)').run(thread.id,req.user.id,req.body.body.trim(),t,t);db.prepare('UPDATE threads SET updated_at=? WHERE id=?').run(t,thread.id);res.json({id:x.lastInsertRowid});
});
app.put('/api/posts/:id',auth,(req,res)=>{
 const p=db.prepare('SELECT * FROM posts WHERE id=?').get(Number(req.params.id));if(!p)return res.status(404).json({error:'Post not found'});if(p.user_id!==req.user.id&&req.user.role!=='admin')return res.status(403).json({error:'Not allowed'});if(!validBody(req.body.body))return res.status(400).json({error:'Body is required'});db.prepare('UPDATE posts SET body=?,edited=1,updated_at=? WHERE id=?').run(req.body.body.trim(),now(),p.id);res.json({ok:true});
});
app.delete('/api/posts/:id',auth,(req,res)=>{const p=db.prepare('SELECT * FROM posts WHERE id=?').get(Number(req.params.id));if(!p)return res.status(404).json({error:'Post not found'});if(p.user_id!==req.user.id&&req.user.role!=='admin')return res.status(403).json({error:'Not allowed'});db.prepare('DELETE FROM posts WHERE id=?').run(p.id);res.json({ok:true})});
app.get('/api/search',(req,res)=>{const q=String(req.query.q||'').trim();if(q.length<2||q.length>80)return res.status(400).json({error:'Search must be 2-80 characters'});res.json({threads:db.prepare(`SELECT DISTINCT t.*,f.name forum_name,u.username,u.display_name FROM threads t JOIN posts p ON p.thread_id=t.id JOIN forums f ON f.id=t.forum_id JOIN users u ON u.id=t.user_id WHERE t.title LIKE ? OR p.body LIKE ? ORDER BY t.updated_at DESC LIMIT 50`).all('%'+q+'%','%'+q+'%')})});
app.get('/api/users/:username',(req,res)=>{const u=db.prepare('SELECT id,username,display_name,role,created_at FROM users WHERE username=?').get(req.params.username);if(!u)return res.status(404).json({error:'User not found'});res.json({user:u})});
app.post('/api/reports',auth,(req,res)=>{const p=db.prepare('SELECT id FROM posts WHERE id=?').get(Number(req.body.post_id));if(!p||!validBody(req.body.reason,500))return res.status(400).json({error:'Invalid report'});db.prepare('INSERT INTO reports(post_id,user_id,reason,created_at) VALUES(?,?,?,?)').run(p.id,req.user.id,req.body.reason.trim(),now());res.json({ok:true})});
app.get('/api/admin/reports',admin,(req,res)=>res.json({reports:db.prepare(`SELECT r.*,p.body,u.username reporter FROM reports r JOIN posts p ON p.id=r.post_id JOIN users u ON u.id=r.user_id WHERE r.resolved=0 ORDER BY r.id DESC`).all()}));
app.post('/api/admin/users/:id/ban',admin,(req,res)=>{db.prepare('UPDATE users SET banned=1 WHERE id=?').run(Number(req.params.id));db.prepare('DELETE FROM sessions WHERE user_id=?').run(Number(req.params.id));res.json({ok:true})});
app.post('/api/admin/threads/:id/lock',admin,(req,res)=>{db.prepare('UPDATE threads SET locked=1 WHERE id=?').run(Number(req.params.id));res.json({ok:true})});
app.post('/api/admin/reports/:id/resolve',admin,(req,res)=>{db.prepare('UPDATE reports SET resolved=1 WHERE id=?').run(Number(req.params.id));res.json({ok:true})});

app.use(express.static(path.join(__dirname,'../public'),{extensions:['html']}));
app.get('/thread',(req,res)=>res.sendFile(path.join(__dirname,'../public/thread.html')));
app.get('/forum',(req,res)=>res.sendFile(path.join(__dirname,'../public/forum.html')));
app.get('/search',(req,res)=>res.sendFile(path.join(__dirname,'../public/search.html')));
app.get('/login',(req,res)=>res.sendFile(path.join(__dirname,'../public/login.html')));
app.get('/register',(req,res)=>res.sendFile(path.join(__dirname,'../public/register.html')));
app.get('/profile',(req,res)=>res.sendFile(path.join(__dirname,'../public/profile.html')));
app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'../public/admin.html')));
app.use((req,res)=>res.status(404).send('Not found'));
app.listen(PORT,HOST,()=>console.log(`${SITE} listening on http://${HOST}:${PORT}`));

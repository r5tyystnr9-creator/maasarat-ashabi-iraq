import express from 'express';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import { rateLimit } from 'express-rate-limit';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, createHash } from 'node:crypto';
import { mkdirSync, readFileSync, unlinkSync, renameSync } from 'node:fs';
import path from 'node:path';

const app = express();
const production = process.env.NODE_ENV === 'production';
const data = path.resolve(process.env.DATA_DIR || 'data');
mkdirSync(path.join(data, 'uploads'), { recursive: true });
const db = new DatabaseSync(path.join(data, 'store.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,admin_id INTEGER,csrf TEXT,expires INTEGER);
CREATE TABLE IF NOT EXISTS categories(id INTEGER PRIMARY KEY,name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,name TEXT NOT NULL,description TEXT,price INTEGER NOT NULL,stock INTEGER NOT NULL,category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,images TEXT NOT NULL,featured INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,created_at TEXT,customer TEXT,items TEXT,subtotal INTEGER,delivery INTEGER,total INTEGER,status TEXT);
`);
const defaults = {name:'مسارات أعشاب العراق',description:'منتجات طبيعية لحياة أفضل',address:'',phone:'',email:'',whatsapp:'',whatsappMessage:'مرحبًا، أريد الاستفسار عن منتجاتكم',whatsappEnabled:true,phoneEnabled:true,logo:'',primary:'#168345',background:'#f6f8f5',text:'#20372a',font:'sans-serif',radius:14,heroTitle:'من الطبيعة… إلى بيتك',heroText:'اكتشف منتجاتنا واختر ما يناسبك بكل سهولة',heroImage:'',delivery:3000,deliveryByProvince:{},notesEnabled:true,areaRequired:true};
if (!db.prepare('SELECT id FROM settings WHERE id=1').get()) db.prepare('INSERT INTO settings VALUES(1,?)').run(JSON.stringify(defaults));
const settings = () => ({...defaults,...JSON.parse(db.prepare('SELECT value FROM settings WHERE id=1').get().value)});
const username = process.env.ADMIN_USERNAME, password = process.env.ADMIN_PASSWORD;
if (!db.prepare('SELECT id FROM admins LIMIT 1').get() && username && password) {
 if(password.length<12) throw new Error('ADMIN_PASSWORD must contain at least 12 characters');
 db.prepare('INSERT INTO admins(username,password) VALUES(?,?)').run(username,bcrypt.hashSync(password,12));
}
app.set('trust proxy', 1);
app.use((req,res,next)=>{res.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"});next();});
app.use(express.json({limit:'256kb'})); app.use(cookieParser());
const hash = t => createHash('sha256').update(t).digest('hex');
function session(req){return req.cookies.session && db.prepare('SELECT * FROM sessions WHERE token=? AND expires>?').get(hash(req.cookies.session),Date.now());}
function auth(req,res,next){const s=session(req);if(!s)return res.status(401).json({error:'يجب تسجيل الدخول'});if(!['GET','HEAD'].includes(req.method)&&req.get('x-csrf-token')!==s.csrf)return res.status(403).json({error:'طلب غير مصرح به'});next();}
function fail(message){const e=new Error(message);e.status=400;throw e;}
function str(v,max=500){return String(v??'').trim().slice(0,max);}
function integer(v,min=0,max=100000000){const n=Number(v);if(!Number.isSafeInteger(n)||n<min||n>max)fail('قيمة رقمية غير صحيحة');return n;}
function imagePath(v){return typeof v==='string'&&/^\/uploads\/[a-f0-9]+\.(png|jpg|webp)$/.test(v);}
const product = r => ({...r,images:JSON.parse(r.images)});
app.get('/api/health',(_req,res)=>{db.prepare('SELECT 1').get();res.json({ok:true});});
app.get('/api/store',(_req,res)=>res.json({settings:settings(),categories:db.prepare('SELECT * FROM categories ORDER BY id').all(),products:db.prepare('SELECT * FROM products ORDER BY id DESC').all().map(product)}));
app.post('/api/login',rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:true,legacyHeaders:false}),async(req,res)=>{
 const user=db.prepare('SELECT * FROM admins WHERE username=?').get(str(req.body.username,80));
 if(!user||!await bcrypt.compare(String(req.body.password||''),user.password))return res.status(401).json({error:'اسم المستخدم أو كلمة المرور غير صحيحة'});
 db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now());
 const token=randomBytes(32).toString('hex'),csrf=randomBytes(24).toString('hex');
 db.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(hash(token),user.id,csrf,Date.now()+8*60*60*1000);
 res.cookie('session',token,{httpOnly:true,secure:production,sameSite:'strict',maxAge:8*60*60*1000,path:'/'}).json({csrf});
});
app.get('/api/admin/session',(req,res)=>{const s=session(req);res.status(s?200:401).json(s?{csrf:s.csrf}:{error:'يجب تسجيل الدخول'});});
app.use('/api/admin',auth);
app.post('/api/admin/logout',(req,res)=>{db.prepare('DELETE FROM sessions WHERE token=?').run(hash(req.cookies.session));res.clearCookie('session',{path:'/'}).json({ok:true});});
app.get('/api/admin/orders',(_req,res)=>res.json(db.prepare('SELECT * FROM orders ORDER BY id DESC').all().map(r=>({...r,customer:JSON.parse(r.customer),items:JSON.parse(r.items)}))));
app.patch('/api/admin/orders/:id',(req,res)=>{if(!['جديد','قيد التجهيز','مكتمل','ملغي'].includes(req.body.status))fail('حالة غير صحيحة');const r=db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status,integer(req.params.id,1));if(!r.changes)return res.status(404).json({error:'الطلب غير موجود'});res.json({ok:true});});
app.post('/api/admin/categories',(req,res)=>{const name=str(req.body.name,100);if(!name)fail('اسم القسم مطلوب');const r=db.prepare('INSERT INTO categories(name) VALUES(?)').run(name);res.status(201).json({id:Number(r.lastInsertRowid)});});
app.put('/api/admin/categories/:id',(req,res)=>{const name=str(req.body.name,100);if(!name)fail('اسم القسم مطلوب');db.prepare('UPDATE categories SET name=? WHERE id=?').run(name,integer(req.params.id,1));res.json({ok:true});});
app.delete('/api/admin/categories/:id',(req,res)=>{db.prepare('DELETE FROM categories WHERE id=?').run(integer(req.params.id,1));res.json({ok:true});});
function productBody(b){const name=str(b.name,200);if(!name)fail('اسم المنتج مطلوب');const images=Array.isArray(b.images)?b.images:[];if(images.length>10||images.some(v=>!imagePath(v)))fail('صور غير صحيحة');const category=b.category_id?integer(b.category_id,1):null;if(category&&!db.prepare('SELECT id FROM categories WHERE id=?').get(category))fail('القسم غير موجود');return [name,str(b.description,10000),integer(b.price),integer(b.stock),category,JSON.stringify(images),b.featured?1:0];}
app.post('/api/admin/products',(req,res)=>{const r=db.prepare('INSERT INTO products(name,description,price,stock,category_id,images,featured) VALUES(?,?,?,?,?,?,?)').run(...productBody(req.body));res.status(201).json({id:Number(r.lastInsertRowid)});});
app.put('/api/admin/products/:id',(req,res)=>{const r=db.prepare('UPDATE products SET name=?,description=?,price=?,stock=?,category_id=?,images=?,featured=? WHERE id=?').run(...productBody(req.body),integer(req.params.id,1));if(!r.changes)return res.status(404).json({error:'المنتج غير موجود'});res.json({ok:true});});
app.delete('/api/admin/products/:id',(req,res)=>{db.prepare('DELETE FROM products WHERE id=?').run(integer(req.params.id,1));res.json({ok:true});});
const upload=multer({dest:path.join(data,'uploads'),limits:{fileSize:5*1024*1024,files:10}});
app.post('/api/admin/uploads',upload.array('images',10),(req,res)=>{
 const paths=[];
 try { for(const f of req.files||[]){const bytes=readFileSync(f.path);const ext=bytes.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))?'png':bytes[0]===255&&bytes[1]===216&&bytes[2]===255?'jpg':bytes.toString('ascii',0,4)==='RIFF'&&bytes.toString('ascii',8,12)==='WEBP'?'webp':null;if(!ext)fail('يسمح بصور PNG وJPEG وWebP فقط');paths.push({file:f,path:'/uploads/'+f.filename+'.'+ext});}
 for(const f of paths)renameSync(f.file.path,path.join(data,f.path));
 }catch(e){for(const f of req.files||[])try{unlinkSync(f.path);}catch{};throw e;}
 res.json({images:paths.map(f=>f.path)});
});
app.put('/api/admin/settings',(req,res)=>{
 const old=settings(),b=req.body,n={...old};
 for(const key of ['name','description','address','phone','email','whatsapp','whatsappMessage','heroTitle','heroText'])if(key in b)n[key]=str(b[key],key==='description'?2000:500);
 for(const key of ['logo','heroImage'])if(key in b){if(b[key]&&!imagePath(b[key]))fail('مسار الصورة غير صحيح');n[key]=b[key];}
 for(const key of ['primary','background','text'])if(key in b){if(!/^#[0-9a-f]{6}$/i.test(b[key]))fail('لون غير صحيح');n[key]=b[key];}
 for(const key of ['whatsappEnabled','phoneEnabled','notesEnabled','areaRequired'])if(key in b)n[key]=Boolean(b[key]);
 if('font'in b){if(!['sans-serif','serif'].includes(b.font))fail('خط غير صحيح');n.font=b.font;}
 if('radius'in b)n.radius=integer(b.radius,0,30);
 if('delivery'in b)n.delivery=integer(b.delivery);
 if('deliveryByProvince'in b){n.deliveryByProvince={};for(const [k,v]of Object.entries(b.deliveryByProvince))n.deliveryByProvince[str(k,50)]=integer(v);}
 if(!n.name)fail('اسم المتجر مطلوب');db.prepare('UPDATE settings SET value=? WHERE id=1').run(JSON.stringify(n));res.json(n);
});
app.post('/api/orders',rateLimit({windowMs:60*1000,limit:10,standardHeaders:true,legacyHeaders:false}),(req,res)=>{
 const b=req.body,s=settings(),c={};for(const key of ['name','phone','province','area','address','notes'])c[key]=str(b[key],key==='notes'?1000:300);
 if(!c.name||!/^\+?[0-9]{10,15}$/.test(c.phone)||!c.province||!c.address||(s.areaRequired&&!c.area))fail('أكمل معلومات الطلب ورقم الهاتف بشكل صحيح');
 const provinces=['بغداد','البصرة','نينوى','أربيل','النجف','كربلاء','بابل','الأنبار','ديالى','كركوك','السليمانية','دهوك','واسط','ميسان','ذي قار','المثنى','القادسية','صلاح الدين'];if(!provinces.includes(c.province))fail('المحافظة غير صحيحة');
 if(!s.notesEnabled)c.notes='';if(!Array.isArray(b.items)||!b.items.length||b.items.length>100)fail('السلة فارغة أو غير صحيحة');
 db.exec('BEGIN IMMEDIATE');try{
 const quantities=new Map();for(const item of b.items){const id=integer(item.id,1),q=integer(item.quantity,1,999);quantities.set(id,(quantities.get(id)||0)+q);}
 const items=[];let subtotal=0;for(const [id,quantity]of quantities){const p=db.prepare('SELECT * FROM products WHERE id=?').get(id);if(!p||quantity>p.stock)fail('منتج غير متوفر أو الكمية أكبر من المخزون');items.push({id,name:p.name,price:p.price,quantity});subtotal+=p.price*quantity;db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(quantity,id);}
 const delivery=s.deliveryByProvince[c.province]??s.delivery,total=subtotal+delivery;
 const r=db.prepare('INSERT INTO orders(created_at,customer,items,subtotal,delivery,total,status) VALUES(?,?,?,?,?,?,?)').run(new Date().toISOString(),JSON.stringify(c),JSON.stringify(items),subtotal,delivery,total,'جديد');db.exec('COMMIT');res.status(201).json({id:Number(r.lastInsertRowid),subtotal,delivery,total});
 }catch(e){db.exec('ROLLBACK');throw e;}
});
app.use('/uploads',express.static(path.join(data,'uploads'),{dotfiles:'deny',setHeaders:res=>res.set('Cache-Control','public, max-age=86400')}));
app.use(express.static('public'));
app.get(['/admin','/products','/product/:id','/cart','/checkout'],(_req,res)=>res.sendFile(path.resolve('public/index.html')));
app.use((err,req,res,next)=>{console.error(err.message);res.status(err.status|| (err instanceof multer.MulterError?400:500)).json({error:err.status||err instanceof multer.MulterError?err.message:'حدث خطأ في الخادم'});});
app.listen(Number(process.env.PORT||3000),'0.0.0.0',()=>console.log('Store server started'));

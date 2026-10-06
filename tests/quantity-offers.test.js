import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { chromium } from '@playwright/test';

async function fixture() {
 const dir=mkdtempSync(path.join(tmpdir(),'quantity-offers-'));
 // Start from the deployed schema, including a historical order without new fields.
 const db=new DatabaseSync(path.join(dir,'store.sqlite'));
 db.exec(`CREATE TABLE products(id INTEGER PRIMARY KEY,name TEXT NOT NULL,description TEXT,price INTEGER NOT NULL,stock INTEGER NOT NULL,category_id INTEGER,images TEXT NOT NULL,featured INTEGER DEFAULT 0);
 CREATE TABLE orders(id INTEGER PRIMARY KEY,created_at TEXT,customer TEXT,items TEXT,subtotal INTEGER,delivery INTEGER,total INTEGER,status TEXT);`);
 db.prepare('INSERT INTO products VALUES(1,?,?,?,?,?,?,?)').run('منتج قديم','وصف محفوظ',15000,30,null,'[]',1);
 db.prepare('INSERT INTO orders VALUES(1,?,?,?,?,?,?,?)').run(new Date().toISOString(),JSON.stringify({name:'طلب قديم',phone:'07701234567',province:'بغداد',area:'منطقة',address:'عنوان',notes:''}),JSON.stringify([{id:1,name:'منتج قديم',price:15000,quantity:1}]),15000,3000,18000,'مكتمل');db.close();
 const password=randomBytes(24).toString('hex'),port=4500+Math.floor(Math.random()*1000),base='http://127.0.0.1:'+port;let processChild;
 async function start(){processChild=spawn(process.execPath,['server.js'],{env:{...process.env,PORT:String(port),DATA_DIR:dir,ADMIN_USERNAME:'test',ADMIN_PASSWORD:password},stdio:'pipe'});let stderr='';processChild.stderr.on('data',d=>stderr+=d);for(let i=0;i<100;i++){if(processChild.exitCode!==null)throw new Error(stderr);try{if((await fetch(base+'/api/health')).ok)return;}catch{}await new Promise(r=>setTimeout(r,100));}throw new Error('Startup failed');}
 async function stop(){if(processChild?.exitCode===null){const ended=new Promise(r=>processChild.once('exit',r));processChild.kill();await ended;}}
 await start();const login=await fetch(base+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:'test',password})});assert.equal(login.status,200);const cookie=login.headers.get('set-cookie').split(';')[0],{csrf}=await login.json();
 async function request(url,method='GET',body){const r=await fetch(base+'/api'+url,{method,headers:{cookie,'Content-Type':'application/json','x-csrf-token':csrf},...(body?{body:JSON.stringify(body)}:{})});return {status:r.status,body:await r.json()};}
 return {base,password,request,start,stop,close:async()=>{await stop();rmSync(dir,{recursive:true,force:true});}};
}
const customer={name:'عميل اختبار',phone:'07701234567',province:'بغداد',area:'منطقة',address:'عنوان'};
const ordinary={name:'منتج عادي',description:'',price:15000,stock:12,images:[]};
const offers=[{quantity:3,totalPrice:35000,deliveryFee:5000,freeDelivery:false,badgeText:'الأكثر طلبًا'},{quantity:3,totalPrice:33000,deliveryFee:9000,freeDelivery:true,badgeText:'وفر أكثر'},{quantity:99,totalPrice:90000,deliveryFee:0,freeDelivery:true,badgeText:''}];

test('safe migration and authoritative offer pricing, mixed shipping, stock and historical snapshots',async()=>{
 const f=await fixture();try{
 let state=(await f.request('/store')).body;assert.equal(state.products[0].saleMode,'normal');assert.deepEqual(state.products[0].quantityOffers,[]);assert.equal(state.products[0].stock,30);
 const old=(await f.request('/admin/orders')).body[0];assert.equal(old.total,18000);assert.equal(old.items[0].price,15000);
 const creation=await f.request('/admin/products','POST',{...ordinary,saleMode:'offers',quantityOffers:offers});assert.equal(creation.status,201);const id=creation.body.id;
 let p=(await f.request('/store')).body.products.find(p=>p.id===id);const [paid,free,large]=p.quantityOffers;assert.notEqual(paid.id,free.id);
 const order=(items,phone=customer.phone)=>f.request('/orders','POST',{...customer,phone,total:1,delivery:0,items});
 let result=await order([{id:1,quantity:2}],'٠٧٧٠١٢٣٤٥٦٧');assert.equal(result.status,201);assert.equal(result.body.total,33000);assert.equal((await f.request('/store')).body.products.find(p=>p.id===1).stock,28);
 result=await order([{id,offerId:paid.id,quantity:3,totalPrice:1,price:1,deliveryFee:0,freeDelivery:true,offer:{...paid,totalPrice:1}}],'٠77٠١2٣٤5٦7');assert.equal(result.status,201);assert.equal(result.body.subtotal,35000);assert.equal(result.body.delivery,5000);assert.equal(result.body.total,40000);
 const savedOrder=(await f.request('/admin/orders')).body.find(o=>o.id===result.body.id);assert.equal(savedOrder.customer.phone,'07701234567');let snapshot=savedOrder.items[0];assert.equal(snapshot.quantity,3);assert.deepEqual(snapshot.offer,paid);assert.equal(snapshot.offerDescription,'3 قطعة — الأكثر طلبًا');
 result=await order([{id,offerId:free.id,quantity:3}],'۰۷۷۰۱۲۳۴۵۶۷');assert.equal(result.status,201);assert.equal(result.body.delivery,0);assert.equal(result.body.total,33000);
 result=await order([{id:1,quantity:1},{id,offerId:free.id,quantity:3}]);assert.equal(result.status,201);assert.equal(result.body.delivery,3000);assert.equal(result.body.total,51000);
 // Invalid submissions must not deduct either product's stock, including a partially processed cart.
 const before=(await f.request('/store')).body.products;
 assert.equal((await order([{id:1,quantity:1},{id,offerId:large.id,quantity:99}])).status,400);
 assert.equal((await order([{id,offerId:'not-a-real-offer',quantity:3}])).status,400);
 assert.equal((await order([{id,offerId:paid.id,quantity:1}])).status,400);
 assert.equal((await order([{id,offerId:paid.id,quantity:3},{id,offerId:free.id,quantity:3}])).status,400);
 assert.deepEqual((await f.request('/store')).body.products,before);
 for(const quantity of [0,-1,1.5,1000])assert.equal((await f.request('/admin/products','POST',{...ordinary,saleMode:'offers',quantityOffers:[{...offers[0],quantity}]})).status,400);
 assert.equal((await f.request('/admin/products','POST',{...ordinary,saleMode:'offers',quantityOffers:[]})).status,400);
 assert.equal((await f.request('/admin/products','POST',{...ordinary,saleMode:'unknown'})).status,400);
 assert.equal((await f.request('/admin/products','POST',{...ordinary,saleMode:'offers',quantityOffers:[{...offers[0],freeDelivery:'false'}]})).status,400);
 // Reordering never changes offer identity; editing never rewrites an existing order.
 const reordered=[{...free,totalPrice:31000},paid,large];assert.equal((await f.request('/admin/products/'+id,'PUT',{...p,stock:3,quantityOffers:reordered})).status,200);
 p=(await f.request('/store')).body.products.find(p=>p.id===id);assert.equal(p.quantityOffers[0].id,free.id);
 result=await order([{id,offerId:free.id,quantity:3,totalPrice:33000}]);assert.equal(result.status,201);assert.equal(result.body.total,31000);
 assert.deepEqual((await f.request('/admin/orders')).body.find(o=>o.items.some(i=>i.offerId===paid.id)).items[0].offer,paid);
 await f.request('/admin/products/'+id,'PUT',{...p,stock:3,quantityOffers:[free]});assert.equal((await order([{id,offerId:paid.id,quantity:3}])).status,400);
 await f.stop();await f.start();state=(await f.request('/store')).body;assert.equal(state.products.find(p=>p.id===id).quantityOffers[0].id,free.id);assert.equal((await f.request('/admin/orders')).body.find(o=>o.id===1).items[0].price,15000);
 }finally{await f.close();}
});

test('browser ordinary two-piece checkout and admin offer creation/edit/reorder/delete with live storefront updates',async()=>{
 const f=await fixture();let browser;try{
 browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 const admin=await browser.newPage(),shop=await browser.newPage({viewport:{width:390,height:844}}),errors=[];
 for(const page of [admin,shop])page.on('pageerror',err=>errors.push(err.message));
 await admin.goto(f.base+'/admin');await admin.locator('[name=username]').fill('test');await admin.locator('[name=password]').fill(f.password);await admin.getByRole('button',{name:'تسجيل الدخول',exact:true}).click();await admin.locator('.stats').first().waitFor();
 async function checkout(){await shop.getByRole('link',{name:/السلة/}).click();await shop.getByRole('link',{name:'إتمام الطلب ←'}).click();for(const [key,value]of Object.entries(customer)){if(key==='province')await shop.locator('[name=province]').selectOption(value);else await shop.locator('[name='+key+']').fill(value);}await shop.getByRole('button',{name:'تأكيد الطلب',exact:true}).click();await shop.getByRole('heading',{name:'تم استلام طلبك'}).waitFor();}
 await shop.goto(f.base+'/product/1');await shop.locator('#detailqty').fill('2');await shop.getByRole('button',{name:'أضف إلى السلة',exact:true}).click();await checkout();assert.equal((await f.request('/store')).body.products.find(p=>p.id===1).stock,28);
 await admin.locator('[data-tab=products]').click();await admin.locator('#newproduct').click();assert.equal(await admin.locator('#offereditor').isVisible(),false);await admin.locator('[name=name]').fill('منتج عروض');await admin.locator('[name=price]').fill('15000');await admin.locator('[name=stock]').fill('9');await admin.locator('#saleMode').selectOption('offers');assert.equal(await admin.locator('#offereditor').isVisible(),true);
 for(const o of offers){await admin.locator('#addoffer').click();const row=admin.locator('.offeredit').last();for(const key of ['quantity','totalPrice','deliveryFee','badgeText'])await row.locator('[data-field='+key+']').fill(String(o[key]));if(o.freeDelivery)await row.locator('[data-field=freeDelivery]').check();}
 // Editing the order of draft rows keeps their unsaved input values.
 await admin.locator('[data-offer-move="1"][data-direction="-1"]').click();assert.equal(await admin.locator('.offeredit').first().locator('[data-field=badgeText]').inputValue(),'وفر أكثر');
 await admin.getByRole('button',{name:'حفظ المنتج',exact:true}).click();await admin.locator('[data-edit]').nth(1).waitFor();let p=(await f.request('/store')).body.products.find(p=>p.name==='منتج عروض');const paid=p.quantityOffers.find(o=>!o.freeDelivery),free=p.quantityOffers.find(o=>o.badgeText==='وفر أكثر'),large=p.quantityOffers.find(o=>o.quantity===99);
 await shop.goto(f.base+'/product/'+p.id);assert.equal(await shop.locator('[name=selectedOffer]:checked').count(),1);assert.equal(await shop.locator('[name=selectedOffer][value="'+large.id+'"]').isDisabled(),true);assert.equal(await shop.locator('#detailqty').count(),0);await shop.locator('[name=selectedOffer][value="'+paid.id+'"]').check();await shop.screenshot({path:'/tmp/quantity-offers-mobile.png',fullPage:true});assert.equal(await shop.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await shop.getByRole('button',{name:'أضف إلى السلة',exact:true}).click();await shop.getByRole('link',{name:/السلة/}).click();assert.equal(await shop.locator('[data-quantity]').count(),0);assert.equal(await shop.locator('.cartinfo .price').textContent(),'٣٥٬٠٠٠ د.ع');await shop.reload();assert.equal(await shop.locator('.cartinfo .price').textContent(),'٣٥٬٠٠٠ د.ع');await checkout();let state=(await f.request('/store')).body;assert.equal(state.products.find(x=>x.id===p.id).stock,6);let os=(await f.request('/admin/orders')).body;assert.equal(os[0].total,40000);
 await shop.goto(f.base+'/product/'+p.id);await shop.locator('[name=selectedOffer][value="'+free.id+'"]').check();await shop.getByRole('button',{name:'أضف إلى السلة',exact:true}).click();await shop.getByRole('link',{name:/السلة/}).click();assert.equal(await shop.locator('#deliveryamount').textContent(),'٠ د.ع');await checkout();assert.equal((await f.request('/store')).body.products.find(x=>x.id===p.id).stock,3);assert.equal((await f.request('/admin/orders')).body[0].total,33000);
 await admin.locator('[data-tab=orders]').click();await admin.locator('[data-order]').first().click();await admin.locator('#orderdetail').getByText('3 قطعة — وفر أكثر',{exact:true}).waitFor();await admin.locator('#orderdetail').getByText('مجاني',{exact:true}).waitFor();
 // Save in admin and observe an already-open product page without reloading it.
 await shop.goto(f.base+'/product/'+p.id);await admin.locator('[data-tab=products]').click();await admin.locator('[data-edit="'+p.id+'"]').click();await admin.locator('.offeredit[data-id="'+free.id+'"]').locator('[data-field=totalPrice]').fill('31000');await admin.getByRole('button',{name:'حفظ المنتج',exact:true}).click();await admin.locator('[data-edit="'+p.id+'"]').waitFor();await shop.waitForFunction(id=>document.querySelector('[name=selectedOffer][value="'+id+'"]')?.closest('label').textContent.includes('٣١'),free.id,{timeout:22000});
 // Removing a selected offer blocks a stale cart instead of falling back to unit pricing.
 await shop.locator('[name=selectedOffer][value="'+paid.id+'"]').check();await shop.getByRole('button',{name:'أضف إلى السلة',exact:true}).click();await shop.getByRole('link',{name:/السلة/}).click();await admin.locator('[data-edit="'+p.id+'"]').click();await admin.locator('.offeredit[data-id="'+paid.id+'"]').getByRole('button',{name:'حذف العرض'}).click();await admin.getByRole('button',{name:'حفظ المنتج',exact:true}).click();await admin.locator('[data-edit="'+p.id+'"]').waitFor();await shop.reload();await shop.getByText('العرض أو الكمية لم يعد متوفرًا؛ أعد الاختيار.').waitFor();assert.equal(await shop.getByRole('link',{name:'إتمام الطلب ←'}).count(),0);
 // Mode toggles hide offers without discarding them and ordinary forms still work.
 await admin.locator('[data-edit="'+p.id+'"]').click();await admin.locator('#saleMode').selectOption('normal');assert.equal(await admin.locator('#offereditor').isVisible(),false);await admin.getByRole('button',{name:'حفظ المنتج',exact:true}).click();await admin.locator('[data-edit="'+p.id+'"]').waitFor();let switched=(await f.request('/store')).body.products.find(x=>x.id===p.id);assert.equal(switched.saleMode,'normal');assert.equal(switched.quantityOffers.length,2);await admin.locator('[data-edit="'+p.id+'"]').click();await admin.locator('#saleMode').selectOption('offers');assert.equal(await admin.locator('.offeredit').count(),2);await admin.getByRole('button',{name:'حفظ المنتج',exact:true}).click();await admin.locator('[data-edit="'+p.id+'"]').waitFor();assert.equal((await f.request('/store')).body.products.find(x=>x.id===p.id).saleMode,'offers');await admin.locator('[data-edit="'+p.id+'"]').click();
 await admin.setViewportSize({width:390,height:844});assert.equal(await admin.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);assert.deepEqual(errors,[]);
 }finally{if(browser)await browser.close();await f.close();}
});

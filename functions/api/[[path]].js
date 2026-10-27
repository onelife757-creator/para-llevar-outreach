const enc=new TextEncoder();
const json=(data,status=200)=>Response.json(data,{status,headers:{'cache-control':'no-store'}});
const hex=a=>Array.from(new Uint8Array(a),b=>b.toString(16).padStart(2,'0')).join('');
const digest=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const hashPin=async(pin,salt)=>hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(salt),iterations:180000,hash:'SHA-256'},await crypto.subtle.importKey('raw',enc.encode(pin),'PBKDF2',false,['deriveBits']),256));
const random=()=>crypto.randomUUID();
const cookie=(token,maxAge)=>'__Host-pl_session='+token+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+maxAge;
async function tables(db){await db.batch([
 db.prepare("CREATE TABLE IF NOT EXISTS members (id TEXT PRIMARY KEY,name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','caller')),pin_salt TEXT NOT NULL,pin_hash TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,member_id TEXT NOT NULL,expires_at TEXT NOT NULL)"),
 db.prepare("CREATE TABLE IF NOT EXISTS leads (id TEXT PRIMARY KEY,business TEXT NOT NULL,category TEXT NOT NULL CHECK(category IN ('wholesale','advertising','retail')),contact TEXT NOT NULL DEFAULT '',email TEXT NOT NULL DEFAULT '',phone TEXT NOT NULL DEFAULT '',website TEXT NOT NULL DEFAULT '',city TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'New',notes TEXT NOT NULL DEFAULT '',due TEXT NOT NULL DEFAULT '',last_sent TEXT NOT NULL DEFAULT '',assigned_to TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE INDEX IF NOT EXISTS idx_pl_leads_assigned ON leads(assigned_to,updated_at)"),
 db.prepare("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY,lead_id TEXT NOT NULL,member_id TEXT NOT NULL,action TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
]);}
async function userFor(req,db){
 const token=(req.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('__Host-pl_session='))?.slice(18);
 if(!token)return null;
 return db.prepare("SELECT m.id,m.name,m.role FROM sessions s JOIN members m ON m.id=s.member_id WHERE s.token_hash=? AND s.expires_at>? AND m.active=1").bind(await digest(token),new Date().toISOString()).first();
}
const fields=['business','category','contact','email','phone','website','city','status','notes','due'];
export async function onRequest(context){
 const {request,env}=context,db=env.PL_DB,url=new URL(request.url),path=url.pathname,method=request.method;
 if(!db)return json({error:'D1 is not connected. Add the PL_DB binding in Cloudflare Pages settings.'},503);
 if(!['GET','HEAD'].includes(method)&&new URL(request.url).origin!==request.headers.get('origin'))return json({error:'Invalid origin.'},403);
 await tables(db);
 if(path==='/api/setup-status'){const row=await db.prepare('SELECT COUNT(*) AS total FROM members').first();return json({needsSetup:!row.total});}
 if(path==='/api/setup'&&method==='POST'){
  if(!env.PL_SETUP_KEY)return json({error:'Set a PL_SETUP_KEY secret in Cloudflare before initial setup.'},503);
  const count=await db.prepare('SELECT COUNT(*) AS total FROM members').first();if(count.total)return json({error:'Owner already configured.'},409);
  const data=await request.json().catch(()=>({}));if(data.setupKey!==env.PL_SETUP_KEY)return json({error:'Incorrect setup key.'},403);
  const name=String(data.name||'').trim(),pin=String(data.pin||'');if(name.length<2||name.length>80||!/^[0-9]{4,8}$/.test(pin))return json({error:'Enter an owner name and a 4 to 8 digit PIN.'},400);
  const salt=random(),id=random();const created=await db.prepare("INSERT INTO members (id,name,role,pin_salt,pin_hash) SELECT ?,?,'owner',?,? WHERE NOT EXISTS(SELECT 1 FROM members)").bind(id,name,salt,await hashPin(pin,salt)).run();
  if(!created.meta?.changes)return json({error:'Already configured.'},409);
  return json({ok:true});
 }
 if(path==='/api/login'&&method==='POST'){
  const data=await request.json().catch(()=>({})),name=String(data.name||'').trim(),pin=String(data.pin||'');
  const member=await db.prepare('SELECT * FROM members WHERE name=? COLLATE NOCASE AND active=1').bind(name).first();
  if(!member||!pin||await hashPin(pin,member.pin_salt)!==member.pin_hash)return json({error:'Invalid account or PIN.'},401);
  const token=random()+random(),expiry=new Date(Date.now()+7*86400000).toISOString();await db.prepare('INSERT INTO sessions(token_hash,member_id,expires_at) VALUES(?,?,?)').bind(await digest(token),member.id,expiry).run();
  return new Response(JSON.stringify({ok:true,user:{id:member.id,name:member.name,role:member.role}}),{headers:{'content-type':'application/json','cache-control':'no-store','set-cookie':cookie(token,7*86400)}});
 }
 const user=await userFor(request,db);
 if(!user)return json({error:'Sign in to Para Llevar Outreach.'},401);
 if(path==='/api/me'&&method==='GET')return json({user});
 if(path==='/api/logout'&&method==='POST'){
  const token=(request.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('__Host-pl_session='))?.slice(18);
  if(token)await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(token)).run();
  return new Response(JSON.stringify({ok:true}),{headers:{'content-type':'application/json','set-cookie':cookie('',0),'cache-control':'no-store'}});
 }
 if(path==='/api/team'&&method==='GET'){
  const {results}=await db.prepare('SELECT id,name,role,active FROM members ORDER BY role,name').all();return json({members:user.role==='owner'?results:results.filter(x=>x.active)});
 }
 if(path==='/api/team'&&method==='POST'){
  if(user.role!=='owner')return json({error:'Owner only.'},403);
  const d=await request.json().catch(()=>({})),name=String(d.name||'').trim(),pin=String(d.pin||'');
  if(name.length<2||name.length>80||!/^[0-9]{4,8}$/.test(pin))return json({error:'Name and 4 to 8 digit PIN required.'},400);
  const salt=random();try{await db.prepare("INSERT INTO members(id,name,role,pin_salt,pin_hash) VALUES(?,?,'caller',?,?)").bind(random(),name,salt,await hashPin(pin,salt)).run();}catch{return json({error:'Could not add team member. Check for duplicate names.'},409);}
  return json({ok:true});
 }
 if(path==='/api/leads'&&method==='GET'){
  const q=user.role==='owner'?db.prepare('SELECT * FROM leads ORDER BY updated_at DESC'):db.prepare('SELECT * FROM leads WHERE assigned_to=? ORDER BY updated_at DESC').bind(user.id);
  const {results}=await q.all();return json({leads:results.map(mapLead)});
 }
 if(path==='/api/leads'&&method==='POST'){
  const d=await request.json().catch(()=>({})),data=validate(d);if(data.error)return json({error:data.error},400);
  const assigned=user.role==='owner'&&d.assigned_to?String(d.assigned_to):user.id;
  const permitted=await db.prepare('SELECT id FROM members WHERE id=? AND active=1').bind(assigned).first();if(!permitted)return json({error:'Unknown assignee.'},400);
  const id=random();
  await db.batch([db.prepare("INSERT INTO leads(id,business,category,contact,email,phone,website,city,status,notes,due,last_sent,assigned_to,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(id,...fields.map(f=>data[f]),'',assigned,user.id),db.prepare('INSERT INTO events(id,lead_id,member_id,action) VALUES(?,?,?,?)').bind(random(),id,user.id,'created')]);
  return json({ok:true,id});
 }
 const match=path.match(/^\/api\/leads\/([^/]+)$/);
 if(match&&method==='PATCH'){
  const id=match[1],lead=await db.prepare('SELECT * FROM leads WHERE id=?').bind(id).first();
  if(!lead||(user.role!=='owner'&&lead.assigned_to!==user.id))return json({error:'Lead not found.'},404);
  const d=await request.json().catch(()=>({})),data=validate({...lead,...d});if(data.error)return json({error:data.error},400);
  const assigned=user.role==='owner'&&d.assigned_to?String(d.assigned_to):lead.assigned_to;
  if(assigned!==lead.assigned_to&&!await db.prepare('SELECT id FROM members WHERE id=? AND active=1').bind(assigned).first())return json({error:'Unknown assignee.'},400);
  const sent=d.recordSent===true?new Date().toISOString():lead.last_sent,due=d.recordSent===true?new Date(Date.now()+3*86400000).toISOString().slice(0,10):data.due,status=d.recordSent===true?'Contacted':data.status;
  await db.batch([db.prepare("UPDATE leads SET business=?,category=?,contact=?,email=?,phone=?,website=?,city=?,status=?,notes=?,due=?,last_sent=?,assigned_to=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(...fields.slice(0,7).map(f=>data[f]),status,data.notes,due,sent,assigned,id),db.prepare('INSERT INTO events(id,lead_id,member_id,action) VALUES(?,?,?,?)').bind(random(),id,user.id,d.recordSent?'manual_send_recorded':'updated')]);
  return json({ok:true});
 }
 return json({error:'Not found.'},404);
}
function validate(d){const out={};for(const name of fields)out[name]=String(d[name]??'').trim();if(!out.business||out.business.length>180)return {error:'Business name required (max 180 characters).'};if(!['wholesale','advertising','retail'].includes(out.category))return {error:'Choose a category.'};if(!['New','Contacted','Interested','Follow-up Due','Negotiating','Closed Won','Closed Lost'].includes(out.status))return {error:'Choose a valid status.'};if(out.email&&(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(out.email)||out.email.length>254))return {error:'Invalid email.'};if(out.due&&!/^\d{4}-\d{2}-\d{2}$/.test(out.due))return {error:'Invalid due date.'};if(out.notes.length>5000)return {error:'Notes too long.'};return out;}
function mapLead(d){return {id:d.id,business:d.business,category:d.category,contact:d.contact,email:d.email,phone:d.phone,website:d.website,city:d.city,status:d.status,notes:d.notes,due:d.due,lastSent:d.last_sent,assigned_to:d.assigned_to};}

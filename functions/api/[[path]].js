const enc=new TextEncoder();
const json=(data,status=200)=>Response.json(data,{status,headers:{'cache-control':'no-store'}});
const hex=a=>Array.from(new Uint8Array(a),b=>b.toString(16).padStart(2,'0')).join('');
const digest=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const hashPin=async(pin,salt)=>hex(await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(salt),iterations:100000,hash:'SHA-256'},await crypto.subtle.importKey('raw',enc.encode(pin),'PBKDF2',false,['deriveBits']),256));
const random=()=>crypto.randomUUID();
const cookie=(token,maxAge)=>'__Host-pl_session='+token+'; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age='+maxAge;
async function tables(db){await db.batch([
 db.prepare("CREATE TABLE IF NOT EXISTS members (id TEXT PRIMARY KEY,name TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','caller')),pin_salt TEXT NOT NULL,pin_hash TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,member_id TEXT NOT NULL,expires_at TEXT NOT NULL)"),
 db.prepare("CREATE TABLE IF NOT EXISTS leads (id TEXT PRIMARY KEY,business TEXT NOT NULL,category TEXT NOT NULL CHECK(category IN ('wholesale','advertising','retail')),contact TEXT NOT NULL DEFAULT '',email TEXT NOT NULL DEFAULT '',phone TEXT NOT NULL DEFAULT '',website TEXT NOT NULL DEFAULT '',city TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'New',notes TEXT NOT NULL DEFAULT '',due TEXT NOT NULL DEFAULT '',last_sent TEXT NOT NULL DEFAULT '',assigned_to TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE INDEX IF NOT EXISTS idx_pl_leads_assigned ON leads(assigned_to,updated_at)"),
 db.prepare("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY,lead_id TEXT NOT NULL,member_id TEXT NOT NULL,action TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS login_limits (identity TEXT PRIMARY KEY,attempts INTEGER NOT NULL DEFAULT 0,blocked_until INTEGER NOT NULL DEFAULT 0)"),
 db.prepare("CREATE TABLE IF NOT EXISTS lead_workspace (lead_id TEXT PRIMARY KEY,research TEXT NOT NULL DEFAULT '',opportunity TEXT NOT NULL DEFAULT '',draft TEXT NOT NULL DEFAULT '',channel TEXT NOT NULL DEFAULT 'email',score INTEGER NOT NULL DEFAULT 50,archived INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS restock_policies (lead_id TEXT PRIMARY KEY,interval_months INTEGER NOT NULL DEFAULT 3,last_checked TEXT NOT NULL DEFAULT '',next_check TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS stock_counts (lead_id TEXT NOT NULL,title TEXT NOT NULL,received INTEGER NOT NULL DEFAULT 0,sold INTEGER NOT NULL DEFAULT 0,returned INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(lead_id,title))"),
 db.prepare("CREATE TABLE IF NOT EXISTS historical_stock (lead_id TEXT NOT NULL,issue TEXT NOT NULL,received INTEGER,remaining INTEGER,source TEXT NOT NULL DEFAULT '',source_date TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(lead_id,issue))"),
 db.prepare("CREATE TABLE IF NOT EXISTS editorial_campaigns (article_url TEXT PRIMARY KEY,title TEXT NOT NULL,subject TEXT NOT NULL,body TEXT NOT NULL,audience TEXT NOT NULL DEFAULT 'stockists',status TEXT NOT NULL DEFAULT 'draft',updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS substack_cache (id INTEGER PRIMARY KEY CHECK(id=1),payload TEXT NOT NULL,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS grant_opportunities (id TEXT PRIMARY KEY,name TEXT NOT NULL,organization TEXT NOT NULL DEFAULT '',url TEXT NOT NULL UNIQUE,deadline TEXT NOT NULL DEFAULT '',amount TEXT NOT NULL DEFAULT '',geography TEXT NOT NULL DEFAULT '',eligibility TEXT NOT NULL DEFAULT '',fit_score INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'To Review',notes TEXT NOT NULL DEFAULT '',discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS agent_runs (id TEXT PRIMARY KEY,agent TEXT NOT NULL,status TEXT NOT NULL,findings TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS prospect_territories (id TEXT PRIMARY KEY,state TEXT NOT NULL,city TEXT NOT NULL,category TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'Queued',last_searched TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE(state,city,category))"),
 db.prepare("CREATE TABLE IF NOT EXISTS prospect_candidates (id TEXT PRIMARY KEY,territory_id TEXT NOT NULL,name TEXT NOT NULL,website TEXT NOT NULL DEFAULT '',city TEXT NOT NULL, state TEXT NOT NULL,category TEXT NOT NULL,source_url TEXT NOT NULL DEFAULT '',fit_notes TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'Review',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS candidate_research (candidate_id TEXT PRIMARY KEY,photo_url TEXT NOT NULL DEFAULT '',contact_url TEXT NOT NULL DEFAULT '',contact_email TEXT NOT NULL DEFAULT '',buyer_name TEXT NOT NULL DEFAULT '',products TEXT NOT NULL DEFAULT '',pitch TEXT NOT NULL DEFAULT '',fit_score INTEGER NOT NULL DEFAULT 0,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
 db.prepare("CREATE TABLE IF NOT EXISTS partnerships (id TEXT PRIMARY KEY,name TEXT NOT NULL,category TEXT NOT NULL,website TEXT NOT NULL,contact TEXT NOT NULL DEFAULT '',contact_url TEXT NOT NULL DEFAULT '',city TEXT NOT NULL DEFAULT '',collaboration TEXT NOT NULL DEFAULT '',value_prop TEXT NOT NULL DEFAULT '',source_url TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'Research',notes TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
]);}
async function userFor(req,db){
 const token=(req.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('__Host-pl_session='))?.slice(18);
 if(!token)return null;
 return db.prepare("SELECT m.id,m.name,m.role FROM sessions s JOIN members m ON m.id=s.member_id WHERE s.token_hash=? AND s.expires_at>? AND m.active=1").bind(await digest(token),new Date().toISOString()).first();
}
const fields=['business','category','contact','email','phone','website','city','status','notes','due'];
async function handleRequest(context){
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
 if(path==='/api/login-accounts'&&method==='GET'){
  const rows=await db.prepare("SELECT name FROM members WHERE active=1 ORDER BY name").all();
  return json({accounts:rows.results.map(row=>row.name)});
 }
 if(path==='/api/login'&&method==='POST'){
  const data=await request.json().catch(()=>({})),name=String(data.name||'').trim(),pin=String(data.pin||'');
  const remoteIp=request.headers.get('CF-Connecting-IP')||'unknown';
  const identity=await digest(remoteIp+'|'+name.toLowerCase());
  const now=Date.now();
  const limit=await db.prepare('SELECT attempts,blocked_until FROM login_limits WHERE identity=?').bind(identity).first();
  if(limit&&limit.blocked_until>now)return json({error:'Too many sign-in attempts. Try again in 15 minutes.'},429);
  const member=await db.prepare('SELECT * FROM members WHERE name=? COLLATE NOCASE AND active=1').bind(name).first();
  const valid=!!member&&!!pin&&await hashPin(pin,member.pin_salt)===member.pin_hash;
  if(!valid){
   const attempts=(limit?.blocked_until&&limit.blocked_until<=now?0:limit?.attempts||0)+1;
   await db.prepare('INSERT INTO login_limits(identity,attempts,blocked_until) VALUES(?,?,?) ON CONFLICT(identity) DO UPDATE SET attempts=excluded.attempts,blocked_until=excluded.blocked_until').bind(identity,attempts,attempts>=5?now+15*60*1000:0).run();
   return json({error:attempts>=5?'Too many sign-in attempts. Try again in 15 minutes.':'Invalid account or PIN.'},attempts>=5?429:401);
  }
  await db.prepare('DELETE FROM login_limits WHERE identity=?').bind(identity).run();
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
 if(path==='/api/substack-feed'&&method==='GET'){
  const target='https://parallevarmagazine.substack.com/feed';
  const cached=await db.prepare('SELECT payload,updated_at FROM substack_cache WHERE id=1').first();
  if(cached&&Date.now()-Date.parse(cached.updated_at.replace(' ','T')+'Z')<6*3600000)return json({...JSON.parse(cached.payload),cached:true});
  let response;
  try{response=await fetch(target,{headers:{'Accept':'application/rss+xml, application/xml, text/xml'},redirect:'follow'});}catch{return cached?json({...JSON.parse(cached.payload),cached:true,stale:true}):json({articles:[],feed:target,unavailable:true},200)}
  if(!response.ok)return cached?json({...JSON.parse(cached.payload),cached:true,stale:true}):json({articles:[],feed:target,unavailable:true,rateLimited:response.status===429});
  const xml=await response.text();
  const decode=x=>String(x||'').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g,'$1').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/<[^>]*>/g,'').trim();
  const get=(item,tag)=>{const match=item.match(new RegExp('<'+tag+'(?:\\s[^>]*)?>([\\s\\S]*?)<\\/'+tag+'>','i'));return decode(match?.[1]||'')};
  const items=(xml.match(/<item(?:\s[^>]*)?>[\s\S]*?<\/item>/gi)||[]).slice(0,30).map(item=>({title:get(item,'title'),url:get(item,'link'),published:get(item,'pubDate'),summary:get(item,'description').slice(0,500),image:(item.match(/<enclosure\b[^>]*url=["']([^"']+)["'][^>]*>/i)?.[1]||item.match(/<media:content\b[^>]*url=["']([^"']+)["'][^>]*>/i)?.[1]||item.match(/<img\b[^>]*src=["']([^"']+)["']/i)?.[1]||'').replace(/&amp;/g,'&')})).filter(item=>item.title&&/^https:\/\/(parallevarmagazine\.substack\.com|substack\.com)\//.test(item.url));
  const payload={articles:items,feed:target};
  if(items.length)await db.prepare('INSERT INTO substack_cache(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=CURRENT_TIMESTAMP').bind(JSON.stringify(payload)).run();
  return json(payload);
 }
 if(path==='/api/territories'&&method==='GET'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const [territories,candidates]=await Promise.all([db.prepare('SELECT * FROM prospect_territories ORDER BY created_at DESC').all(),db.prepare("SELECT * FROM prospect_candidates ORDER BY created_at DESC LIMIT 500").all()]);
  const research=(await db.prepare('SELECT * FROM candidate_research').all()).results;return json({territories:territories.results,candidates:candidates.results.map(c=>({...c,...(research.find(x=>x.candidate_id===c.id)||{})}))});
 }
 if(path==='/api/territories'&&method==='POST'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const d=await request.json().catch(()=>({})),state=String(d.state||'').trim().toUpperCase(),city=String(d.city||'').trim(),category=String(d.category||'').trim();
  if(!/^[A-Z]{2}$/.test(state)||city.length<2||city.length>120||!['bookstores','hotels','museum shops','food shops','gift shops','newsstands'].includes(category))return json({error:'Choose a valid US state, city and store category.'},400);
  await db.prepare("INSERT INTO prospect_territories(id,state,city,category) VALUES(?,?,?,?) ON CONFLICT(state,city,category) DO NOTHING").bind(random(),state,city,category).run();
  return json({ok:true});
 }
 const territoryMatch=path.match(/^\/api\/territories\/([^/]+)$/);
 if(territoryMatch&&method==='PATCH'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const d=await request.json().catch(()=>({}));if(!['Queued','Researching','Reviewed'].includes(d.status))return json({error:'Invalid status.'},400);
  await db.prepare("UPDATE prospect_territories SET status=?,last_searched=CASE WHEN ?='Reviewed' THEN CURRENT_TIMESTAMP ELSE last_searched END WHERE id=?").bind(d.status,d.status,territoryMatch[1]).run();return json({ok:true});
 }
 if(path==='/api/prospect-candidates'&&method==='POST'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const d=await request.json().catch(()=>({})),name=String(d.name||'').trim(),website=String(d.website||'').trim(),source=String(d.source_url||'').trim();
  const t=await db.prepare('SELECT * FROM prospect_territories WHERE id=?').bind(String(d.territory_id||'')).first();
  if(!t||name.length<2||name.length>180||!/^https:\/\//.test(source)||!/^https:\/\//.test(website))return json({error:'Select a territory and provide verified website and source URLs.'},400);
  const existing=(await db.prepare("SELECT business,city FROM leads").all()).results.some(l=>l.business.toLowerCase().trim()===name.toLowerCase()&&(!l.city||l.city.toLowerCase().trim()===t.city.toLowerCase()));
  if(existing)return json({error:'Already in the shared lead database.'},409);
  const same=await db.prepare("SELECT id FROM prospect_candidates WHERE lower(name)=lower(?) AND lower(city)=lower(?) AND state=?").bind(name,t.city,t.state).first();
  if(same)return json({error:'Candidate already recorded.'},409);
  const id=random();await db.prepare("INSERT INTO prospect_candidates(id,territory_id,name,website,city,state,category,source_url,fit_notes) VALUES(?,?,?,?,?,?,?,?,?)").bind(id,t.id,name,website,t.city,t.state,t.category,source,String(d.fit_notes||'').slice(0,2000)).run();
  const photo=String(d.photo_url||''),contact=String(d.contact_url||''),email=String(d.contact_email||''),buyer=String(d.buyer_name||''),products=String(d.products||''),pitch=String(d.pitch||''),score=Math.max(0,Math.min(100,Math.round(Number(d.fit_score)||0)));
  if([photo,contact].every(x=>!x||/^https:\/\//.test(x))&&(!email||/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)))await db.prepare("INSERT INTO candidate_research(candidate_id,photo_url,contact_url,contact_email,buyer_name,products,pitch,fit_score) VALUES(?,?,?,?,?,?,?,?)").bind(id,photo.slice(0,1200),contact.slice(0,1200),email.slice(0,250),buyer.slice(0,200),products.slice(0,3000),pitch.slice(0,4000),score).run();
  return json({ok:true});
 }
 if(path==='/api/partnerships'&&method==='GET'){
 if(user.role!=='owner')return json({error:'Owner access required.'},403);
 const {results}=await db.prepare('SELECT * FROM partnerships ORDER BY created_at DESC LIMIT 300').all();return json({partnerships:results});
 }
 if(path==='/api/partnerships'&&method==='POST'){
 if(user.role!=='owner')return json({error:'Owner access required.'},403);
 const d=await request.json().catch(()=>({})),name=String(d.name||'').trim(),website=String(d.website||'').trim(),category=String(d.category||'').trim();
 if(!name||name.length>180||!/^https:\/\//.test(website)||!['Brands','Restaurants & Chefs','Hotels','Events','Cultural Organizations','Media','Other'].includes(category))return json({error:'Enter a valid name, category and official HTTPS website.'},400);
 const existing=await db.prepare('SELECT id FROM partnerships WHERE lower(name)=lower(?) AND website=?').bind(name,website).first();if(existing)return json({error:'Already in the partnership pipeline.'},409);
 const fields=['contact','contact_url','city','collaboration','value_prop','source_url','notes'].map(k=>String(d[k]||'').trim().slice(0,2000));
 if([fields[1],fields[5]].some(x=>x&&!/^https:\/\//.test(x)))return json({error:'Contact and source links must use HTTPS.'},400);
 await db.prepare('INSERT INTO partnerships(id,name,category,website,contact,contact_url,city,collaboration,value_prop,source_url,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(random(),name,category,website,...fields).run();return json({ok:true});
 }
 const partnershipMatch=path.match(/^\/api\/partnerships\/([^/]+)$/);
 if(partnershipMatch&&method==='PATCH'){
 if(user.role!=='owner')return json({error:'Owner access required.'},403);
 const d=await request.json().catch(()=>({}));
 if(!['Research','Qualified','Contacted','In Conversation','Proposal','Partnered','Declined'].includes(d.status))return json({error:'Invalid partnership status.'},400);
 await db.prepare('UPDATE partnerships SET status=? WHERE id=?').bind(d.status,partnershipMatch[1]).run();return json({ok:true});
 }
 if(path==='/api/agent-runs'&&method==='GET'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const {results}=await db.prepare('SELECT id,agent,status,findings,created_at FROM agent_runs ORDER BY created_at DESC LIMIT 100').all();
  return json({runs:results});
 }
 if(path==='/api/agent-runs'&&method==='POST'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const d=await request.json().catch(()=>({}));
  if(!['restock','stockist','grants','editorial','partnerships'].includes(d.agent))return json({error:'Unknown agent.'},400);
  let findings=[];
  if(d.agent==='restock'){
   const {results}=await db.prepare("SELECT l.id,l.business,l.city,p.next_check,p.interval_months FROM restock_policies p JOIN leads l ON l.id=p.lead_id LEFT JOIN lead_workspace w ON w.lead_id=l.id WHERE l.category='wholesale' AND COALESCE(w.archived,0)=0 AND p.next_check<>'' AND p.next_check<=date('now') ORDER BY p.next_check LIMIT 200").all();
   findings=results.map(r=>({lead_id:r.id,business:r.business,city:r.city,due:r.next_check,message:'Check current inventory and ask whether they would like to restock.'}));
  }else if(d.agent==='stockist'){
   const {results}=await db.prepare("SELECT t.id,t.city,t.state,t.category,t.status,COUNT(c.id) candidate_count FROM prospect_territories t LEFT JOIN prospect_candidates c ON c.territory_id=t.id WHERE t.status!='Reviewed' GROUP BY t.id ORDER BY CASE t.status WHEN 'Researching' THEN 0 ELSE 1 END,t.created_at LIMIT 30").all();
   findings=results.map(r=>({business:r.city+', '+r.state,category:r.category,due:r.status,message:r.candidate_count+' candidates saved. Research official websites, retail assortment, contact paths and independent publications; verify before adding.'}));
  }else if(d.agent==='grants'){
   const {results}=await db.prepare("SELECT name,deadline,status,eligibility,geography FROM grant_opportunities WHERE status IN ('To Review','Eligible','Applying') ORDER BY CASE WHEN deadline='' THEN 1 ELSE 0 END,deadline LIMIT 40").all();
   findings=results.map(r=>({business:r.name,due:r.deadline||'Unconfirmed',message:r.status+' · Verify application remains open, entity eligibility, location requirements and funding restrictions. '+(r.eligibility?'Eligibility notes available.':'Eligibility research missing.')}));
  }else if(d.agent==='partnerships'){
   const {results}=await db.prepare("SELECT name,category,collaboration,value_prop,status FROM partnerships WHERE status IN ('Research','Qualified','In Conversation','Proposal') ORDER BY created_at DESC LIMIT 40").all();
   findings=results.map(r=>({business:r.name,due:r.status,message:r.category+' · Opportunity: '+(r.collaboration||'not defined')+' · Mutual value: '+(r.value_prop||'needs research')}));
  }else{
   const {results}=await db.prepare("SELECT title,article_url,audience,updated_at FROM editorial_campaigns WHERE status='draft' ORDER BY updated_at DESC LIMIT 40").all();
   findings=results.map(r=>({business:r.title,due:r.updated_at,message:'Review article link, segment, subject, formatting and personalized message before approving distribution to '+r.audience+'.'}));
  }
  const id=random();await db.prepare('INSERT INTO agent_runs(id,agent,status,findings,created_by) VALUES(?,?,?,?,?)').bind(id,d.agent,'review',JSON.stringify(findings),user.id).run();
  return json({ok:true,id,count:findings.length,findings});
 }
 if(path==='/api/grants'&&method==='GET'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const {results}=await db.prepare('SELECT * FROM grant_opportunities ORDER BY CASE WHEN deadline IS NULL OR deadline="" THEN 1 ELSE 0 END,deadline,updated_at DESC').all();
  return json({grants:results});
 }
 if(path==='/api/grants'&&method==='POST'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const d=await request.json().catch(()=>({}));
  const name=String(d.name||'').trim(),url=String(d.url||'').trim(),organization=String(d.organization||'').trim();
  if(!name||name.length>250||!/^https:\/\//i.test(url)||url.length>1500)return json({error:'Enter a grant name and an official HTTPS application URL.'},400);
  const status=['To Review','Eligible','Applying','Submitted','Awarded','Not Eligible','Closed'].includes(d.status)?d.status:'To Review';
  const deadline=String(d.deadline||'');if(deadline&&!/^\d{4}-\d{2}-\d{2}$/.test(deadline))return json({error:'Use YYYY-MM-DD for the deadline.'},400);
  const values=[name,organization.slice(0,250),url,deadline,String(d.amount||'').slice(0,150),String(d.geography||'').slice(0,250),String(d.eligibility||'').slice(0,4000),Math.max(0,Math.min(100,Math.round(Number(d.fit_score)||0))),status,String(d.notes||'').slice(0,5000)];
  await db.prepare('INSERT INTO grant_opportunities(id,name,organization,url,deadline,amount,geography,eligibility,fit_score,status,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET name=excluded.name,organization=excluded.organization,deadline=excluded.deadline,amount=excluded.amount,geography=excluded.geography,eligibility=excluded.eligibility,fit_score=excluded.fit_score,status=excluded.status,notes=excluded.notes,updated_at=CURRENT_TIMESTAMP').bind(random(),...values).run();
  return json({ok:true});
 }
 const grantMatch=path.match(/^\/api\/grants\/([^/]+)$/);
 if(grantMatch&&method==='PATCH'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const d=await request.json().catch(()=>({}));const allowed=['To Review','Eligible','Applying','Submitted','Awarded','Not Eligible','Closed'];
  if(!allowed.includes(d.status))return json({error:'Invalid grant status.'},400);
  await db.prepare('UPDATE grant_opportunities SET status=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(d.status,String(d.notes||'').slice(0,5000),grantMatch[1]).run();return json({ok:true});
 }
 if(path==='/api/editorial-campaigns'&&method==='GET'){
  const {results}=await db.prepare('SELECT * FROM editorial_campaigns ORDER BY updated_at DESC').all();
  return json({campaigns:results});
 }
 if(path==='/api/editorial-campaigns'&&method==='POST'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const d=await request.json().catch(()=>({}));
  const article_url=String(d.article_url||'').trim(),title=String(d.title||'').trim(),subject=String(d.subject||'').trim(),body=String(d.body||''),audience=String(d.audience||'stockists');
  if(!/^https:\/\/(parallevarmagazine\.substack\.com|substack\.com)\//.test(article_url)||article_url.length>1000)return json({error:'Choose an article from the Para Llevar publication.'},400);
  if(!title||title.length>300||!subject||subject.length>300||!body||body.length>10000||!['stockists','advertisers','retail','all'].includes(audience))return json({error:'Check subject, message, and audience.'},400);
  await db.prepare("INSERT INTO editorial_campaigns(article_url,title,subject,body,audience) VALUES(?,?,?,?,?) ON CONFLICT(article_url) DO UPDATE SET title=excluded.title,subject=excluded.subject,body=excluded.body,audience=excluded.audience,updated_at=CURRENT_TIMESTAMP").bind(article_url,title,subject,body,audience).run();
  return json({ok:true,status:'draft'});
 }
 if(path==='/api/import-stockists'&&method==='POST'){
  if(user.role!=='owner')return json({error:'Owner access required.'},403);
  const payload=await request.json().catch(()=>({}));
  if(!Array.isArray(payload.records)||payload.records.length>20)return json({error:'Upload records in batches of 20 or fewer.'},400);
  const tidy=x=>String(x||'').trim();
  const key=x=>tidy(x).toLowerCase().replace(/[^a-z0-9]/g,'').replace(/newsstand/g,'newstand');
  let added=0,skipped=0,stockAdded=0;
  const existingRows=(await db.prepare("SELECT id,business,city FROM leads WHERE category='wholesale'").all()).results;
  for(const raw of payload.records){
   const name=tidy(raw.business).slice(0,180),city=tidy(raw.city).slice(0,180);
   if(!name){skipped++;continue}
   const matched=existingRows.find(x=>key(x.business)===key(name)&&(key(x.city)===key(city)||!key(x.city)||!key(city)));
   let id=matched?.id;
   if(!id){
    id=random();
    const contact=tidy(raw.contact).slice(0,250),email=/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(tidy(raw.email))?tidy(raw.email).slice(0,254):'';
    const notes=('Imported source: '+tidy(raw.source)+'\\n'+tidy(raw.notes)).slice(0,5000);
    await db.prepare("INSERT INTO leads(id,business,category,contact,email,city,status,notes,assigned_to,created_by) VALUES(?,?,'wholesale',?,?,?,'New',?,?,?)").bind(id,name,contact,email,city,notes,user.id,user.id).run();
    await db.prepare("INSERT INTO events(id,lead_id,member_id,action) VALUES(?,?,?,?)").bind(random(),id,user.id,'imported_from_spreadsheet').run();
    existingRows.push({id,business:name,city});
    added++;
   }else skipped++;
   // Preserve source-reported Issue 5 counts separately from live stock.
   if(raw.inventory&&/issue 5/i.test(tidy(raw.notes))){
    const qty=Number(raw.inventory.received),rem=Number(raw.inventory.remaining);
    const received=Number.isInteger(qty)&&qty>=0?qty:null;
    const remaining=Number.isInteger(rem)&&rem>=0?rem:null;
    if(received!==null||remaining!==null){
     await db.prepare("INSERT INTO historical_stock(lead_id,issue,received,remaining,source,source_date) VALUES(?,'Issue 5',?,?,?,?) ON CONFLICT(lead_id,issue) DO UPDATE SET received=excluded.received,remaining=excluded.remaining,source=excluded.source,source_date=excluded.source_date,updated_at=CURRENT_TIMESTAMP").bind(id,received,remaining,tidy(raw.source),tidy(raw.inventory.sentDate)).run();
     stockAdded++;
    }
   }
  }
  return json({ok:true,added,skipped,stockAdded});
 }
 if(path==='/api/historical-stock'&&method==='GET'){
  const {results}=await db.prepare("SELECT h.* FROM historical_stock h JOIN leads l ON l.id=h.lead_id WHERE ?='owner' OR l.assigned_to=?").bind(user.role,user.id).all();
  return json({history:results});
 }
 if(path==='/api/stock'&&method==='GET'){
  const {results}=await db.prepare("SELECT s.* FROM stock_counts s JOIN leads l ON l.id=s.lead_id WHERE ?='owner' OR l.assigned_to=?").bind(user.role,user.id).all();
  return json({stock:results});
 }
 const stockMatch=path.match(/^\/api\/stock\/([^/]+)$/);
 if(stockMatch&&method==='PATCH'){
  const lead=await db.prepare("SELECT id,assigned_to,category FROM leads WHERE id=?").bind(stockMatch[1]).first();
  if(!lead||(user.role!=='owner'&&lead.assigned_to!==user.id))return json({error:'No access to this stockist.'},403);
  if(lead.category!=='wholesale')return json({error:'Only wholesale stockists can hold inventory.'},400);
  const d=await request.json().catch(()=>({}));
  if(!['PARA LLEVAR Magazine','Check Please'].includes(d.title))return json({error:'Choose a valid publication.'},400);
  const nums=['received','sold','returned'].map(k=>Number(d[k]));
  if(nums.some(n=>!Number.isInteger(n)||n<0||n>1000000))return json({error:'Enter whole numbers of zero or greater.'},400);
  if(nums[1]+nums[2]>nums[0])return json({error:'Sold and returned cannot exceed copies received.'},400);
  await db.batch([
   db.prepare("INSERT INTO stock_counts(lead_id,title,received,sold,returned) VALUES(?,?,?,?,?) ON CONFLICT(lead_id,title) DO UPDATE SET received=excluded.received,sold=excluded.sold,returned=excluded.returned,updated_at=CURRENT_TIMESTAMP").bind(lead.id,d.title,...nums),
   db.prepare("INSERT INTO events(id,lead_id,member_id,action) VALUES(?,?,?,?)").bind(random(),lead.id,user.id,'inventory_updated')
  ]);
  return json({ok:true,remaining:nums[0]-nums[1]-nums[2]});
 }
 if(path==='/api/restock'&&method==='GET'){
  const {results}=await db.prepare("SELECT p.*,l.business,l.category,l.assigned_to FROM restock_policies p JOIN leads l ON l.id=p.lead_id WHERE ?='owner' OR l.assigned_to=? ORDER BY p.next_check").bind(user.role,user.id).all();
  return json({policies:results});
 }
 const restockMatch=path.match(/^\/api\/restock\/([^/]+)$/);
 if(restockMatch&&method==='PATCH'){
  const lead=await db.prepare("SELECT id,assigned_to,category FROM leads WHERE id=?").bind(restockMatch[1]).first();
  if(!lead||(user.role!=='owner'&&lead.assigned_to!==user.id))return json({error:'No access to this stockist.'},403);
  if(lead.category!=='wholesale')return json({error:'Restock scheduling is for wholesale stockists.'},400);
  const d=await request.json().catch(()=>({}));
  const months=Number(d.interval_months);
  if(!Number.isInteger(months)||months<1||months>24)return json({error:'Choose 1 to 24 months.'},400);
  const last=String(d.last_checked||'');
  if(last&&!/^\\d{4}-\\d{2}-\\d{2}$/.test(last))return json({error:'Enter a valid date.'},400);
  const base=last?new Date(last+'T12:00:00Z'):new Date();
  if(Number.isNaN(base.getTime()))return json({error:'Invalid check-in date.'},400);
  const day=base.getUTCDate();
  const target=new Date(Date.UTC(base.getUTCFullYear(),base.getUTCMonth()+months,1,12));
  const monthEnd=new Date(Date.UTC(target.getUTCFullYear(),target.getUTCMonth()+1,0,12)).getUTCDate();
  target.setUTCDate(Math.min(day,monthEnd));
  const next=target.toISOString().slice(0,10);
  await db.batch([
   db.prepare("INSERT INTO restock_policies(lead_id,interval_months,last_checked,next_check) VALUES(?,?,?,?) ON CONFLICT(lead_id) DO UPDATE SET interval_months=excluded.interval_months,last_checked=excluded.last_checked,next_check=excluded.next_check,updated_at=CURRENT_TIMESTAMP").bind(lead.id,months,last,next),
   db.prepare("INSERT INTO events(id,lead_id,member_id,action) VALUES(?,?,?,?)").bind(random(),lead.id,user.id,'restock_schedule_updated')
  ]);
  return json({ok:true,next_check:next});
 }
 if(path==='/api/workspace'&&method==='GET'){
  const {results}=await db.prepare("SELECT w.* FROM lead_workspace w JOIN leads l ON l.id=w.lead_id WHERE ?='owner' OR l.assigned_to=?").bind(user.role,user.id).all();
  return json({workspace:results});
 }
 const workspaceMatch=path.match(/^\/api\/workspace\/([^/]+)$/);
 if(workspaceMatch&&method==='PATCH'){
  const id=workspaceMatch[1],lead=await db.prepare("SELECT id,assigned_to FROM leads WHERE id=?").bind(id).first();
  if(!lead||(user.role!=='owner'&&lead.assigned_to!==user.id))return json({error:'No access to this business.'},403);
  const d=await request.json().catch(()=>({}));
  const current=await db.prepare("SELECT * FROM lead_workspace WHERE lead_id=?").bind(id).first()||{};
  const research=String(d.research??current.research??'').slice(0,15000);
  const opportunity=String(d.opportunity??current.opportunity??'').slice(0,8000);
  const draft=String(d.draft??current.draft??'').slice(0,12000);
  const channel=['email','dm','phone'].includes(d.channel)?d.channel:(current.channel||'email');
  const score=Math.max(1,Math.min(100,Number.isFinite(Number(d.score))?Math.round(Number(d.score)):(current.score||50)));
  if(d.archived!==undefined&&user.role!=='owner')return json({error:'Only the Owner can archive or restore businesses.'},403);
  const archived=user.role==='owner'&&d.archived!==undefined?(d.archived?1:0):(current.archived||0);
  await db.batch([
   db.prepare("INSERT INTO lead_workspace(lead_id,research,opportunity,draft,channel,score,archived) VALUES(?,?,?,?,?,?,?) ON CONFLICT(lead_id) DO UPDATE SET research=excluded.research,opportunity=excluded.opportunity,draft=excluded.draft,channel=excluded.channel,score=excluded.score,archived=excluded.archived,updated_at=CURRENT_TIMESTAMP").bind(id,research,opportunity,draft,channel,score,archived),
   db.prepare("INSERT INTO events(id,lead_id,member_id,action) VALUES(?,?,?,?)").bind(random(),id,user.id,d.archived!==undefined?(archived?'archived':'restored'):'workspace_updated')
  ]);
  return json({ok:true});
 }
 if(path==='/api/activity'&&method==='GET'){
  const leadId=url.searchParams.get('leadId');
  if(!leadId)return json({error:'Lead ID required.'},400);
  const lead=await db.prepare('SELECT assigned_to FROM leads WHERE id=?').bind(leadId).first();
  if(!lead||(user.role!=='owner'&&lead.assigned_to!==user.id))return json({error:'No access.'},403);
  const {results}=await db.prepare('SELECT e.action,e.created_at,m.name AS actor FROM events e LEFT JOIN members m ON m.id=e.member_id WHERE e.lead_id=? ORDER BY e.created_at DESC LIMIT 100').bind(leadId).all();
  return json({activity:results});
 }
 if(path==='/api/leads'&&method==='GET'){
  const q=user.role==='owner'?db.prepare('SELECT * FROM leads ORDER BY updated_at DESC'):db.prepare('SELECT * FROM leads WHERE assigned_to=? ORDER BY updated_at DESC').bind(user.id);
  const {results}=await q.all();return json({leads:results.map(mapLead)});
 }
 if(path==='/api/claimed'&&method==='GET'){
  if(user.role==='owner')return json({claimed:[]});
  const {results}=await db.prepare("SELECT l.business,l.city,l.category FROM leads l WHERE l.assigned_to<>? ORDER BY l.business COLLATE NOCASE").bind(user.id).all();
  return json({claimed:results});
 }
 if(path==='/api/leads'&&method==='POST'){
  const d=await request.json().catch(()=>({})),data=validate(d);if(data.error)return json({error:data.error},400);
  const existing=await db.prepare("SELECT id,category FROM leads WHERE LOWER(TRIM(business))=LOWER(TRIM(?)) AND (LOWER(TRIM(city))=LOWER(TRIM(?)) OR TRIM(city)='' OR TRIM(?)='') LIMIT 1").bind(data.business,data.city,data.city).first();
  if(existing)return json({error:'This business is already in the shared lead database. Ask the Owner to review or reassign it rather than creating a second record.'},409);
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

export async function onRequest(context){
 try{return await handleRequest(context)}catch(error){console.error('Para Llevar API error',error);return json({error:'Server setup error. Please check Cloudflare Functions logs.',detail:error instanceof Error?error.message:'Unknown error'},500)}
}

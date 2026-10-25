
// Web Push (RFC 8291 + RFC 8292), implemented with Cloudflare Web Crypto; no npm dependencies.
const pEnc=new TextEncoder();
const pB64=s=>{const a=atob(String(s).replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-String(s).length%4)%4));return Uint8Array.from(a,c=>c.charCodeAt(0))};
const pUrl=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const pJoin=(...parts)=>{const a=parts.map(x=>x instanceof Uint8Array?x:new Uint8Array(x)),out=new Uint8Array(a.reduce((n,x)=>n+x.length,0));let i=0;for(const x of a){out.set(x,i);i+=x.length}return out};
const pHKDF=async(ikm,salt,info,n)=>{const key=await crypto.subtle.importKey('raw',salt,'HMAC',false,['sign']);const prk=await crypto.subtle.sign('HMAC',key,ikm);const prkKey=await crypto.subtle.importKey('raw',prk,'HMAC',false,['sign']);return new Uint8Array(await crypto.subtle.sign('HMAC',prkKey,pJoin(info,new Uint8Array([1])))).slice(0,n)};
const pInfo=s=>pEnc.encode(s+'\0');
async function pEncrypt(sub,payload){
 const clientPublic=pB64(sub.p256dh),auth=pB64(sub.auth);
 if(clientPublic.length!==65||auth.length!==16)throw Error('Invalid subscription keys');
 const server=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
 const remote=await crypto.subtle.importKey('raw',clientPublic,{name:'ECDH',namedCurve:'P-256'},false,[]);
 const shared=new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:remote},server.privateKey,256));
 const serverPublic=new Uint8Array(await crypto.subtle.exportKey('raw',server.publicKey));
 const prk=await pHKDF(shared,auth,pInfo('Content-Encoding: auth'),32);
 const ikm=await pHKDF(prk,new Uint8Array(32),pJoin(pInfo('WebPush: info'),clientPublic,serverPublic),32);
 const salt=crypto.getRandomValues(new Uint8Array(16));
 const cek=await pHKDF(ikm,salt,pInfo('Content-Encoding: aes128gcm'),16);
 const nonce=await pHKDF(ikm,salt,pInfo('Content-Encoding: nonce'),12);
 const aes=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['encrypt']);
 const plain=pJoin(pEnc.encode(JSON.stringify(payload)),new Uint8Array([2]));
 const cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce},aes,plain));
 const rs=new Uint8Array([0,0,16,0]);
 return pJoin(salt,rs,new Uint8Array([serverPublic.length]),serverPublic,cipher);
}
async function pJwt(endpoint,env){
 const jwk=JSON.parse(env.VAPID_PRIVATE_JWK||'{}');
 const key=await crypto.subtle.importKey('jwk',jwk,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
 const origin=new URL(endpoint).origin;
 const header=pUrl(pEnc.encode(JSON.stringify({typ:'JWT',alg:'ES256'})));
 const payload=pUrl(pEnc.encode(JSON.stringify({aud:origin,exp:Math.floor(Date.now()/1000)+3600,sub:env.VAPID_SUBJECT||'https://ping-lah-sg.pages.dev'})));
 const input=header+'.'+payload;
 const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,pEnc.encode(input));
 return input+'.'+pUrl(sig);
}
async function pSendOne(env,sub,payload){
 const endpoint=new URL(sub.endpoint);if(endpoint.protocol!=='https:'||!['443',''].includes(endpoint.port))throw Error('Invalid push endpoint');
 // Only known push service domains may be contacted (SSRF protection).
 const h=endpoint.hostname.toLowerCase();
 if(!(/(^|\.)push\.services\.mozilla\.com$|(^|\.)fcm\.googleapis\.com$|(^|\.)updates\.push\.services\.mozilla\.com$|(^|\.)notify\.windows\.com$|(^|\.)push\.apple\.com$|(^|\.)web\.push\.apple\.com$|(^|\.)push\.safari\.apple\.com$/.test(h)))throw Error('Unrecognized push service');
 const encrypted=await pEncrypt(sub,payload);
 const jwt=await pJwt(sub.endpoint,env);
 const response=await fetch(sub.endpoint,{method:'POST',headers:{'Content-Type':'application/octet-stream','Content-Encoding':'aes128gcm','TTL':'86400','Authorization':'vapid t='+jwt+', k='+env.VAPID_PUBLIC_KEY},body:encrypted});
 if(response.status===404||response.status===410){await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint=?').bind(sub.endpoint).run();return 'expired'}
 if(!response.ok)throw Error('Push provider HTTP '+response.status);
 return 'sent';
}
async function pNotify(env,recipient,payload){
 if(!env.VAPID_PRIVATE_JWK||!env.VAPID_PUBLIC_KEY)return;
 const result=await env.DB.prepare('SELECT endpoint,p256dh,auth FROM push_subscriptions WHERE user_id=? LIMIT 12').bind(recipient).all();
 const settled=await Promise.allSettled((result.results||[]).map(s=>pSendOne(env,s,payload)));
 const errors=settled.filter(x=>x.status==='rejected').map(x=>String(x.reason?.message||x.reason||'Unknown error').slice(0,180));
 return {devices:settled.length,sent:settled.filter(x=>x.status==='fulfilled'&&x.value==='sent').length,expired:settled.filter(x=>x.status==='fulfilled'&&x.value==='expired').length,failed:errors.length,errors};
}

const J=(v,s=200)=>new Response(JSON.stringify(v),{status:s,headers:{'content-type':'application/json','cache-control':'no-store'}});
const hash=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(x=>x.toString(16).padStart(2,'0')).join('');
const uid=()=>crypto.randomUUID();const now=()=>Date.now();const alphabet='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';const code=()=>Array.from(crypto.getRandomValues(new Uint8Array(8))).map(x=>alphabet[x%alphabet.length]).join('');
const clean=async env=>{const t=now();await env.DB.prepare('DELETE FROM voice_blobs WHERE expires_at <= ?').bind(t).run();await env.DB.prepare('DELETE FROM messages WHERE expires_at <= ?').bind(t).run();await env.DB.prepare('DELETE FROM rate_limits WHERE expires_at <= ?').bind(t).run()};
export async function onRequest({request,env,params,context}){try{
 // Public radio directory endpoint. Works without account or D1 and avoids browser CORS failures.
 const publicRoute='/'+(params.path||[]).join('/');
 if(publicRoute==='/radio/stations'&&request.method==='GET'){
   const country=(new URL(request.url).searchParams.get('country')||'SG').toUpperCase();
   if(!/^[A-Z]{2}$/.test(country))return J({error:'Invalid country code'},400);
   const hosts=['de1.api.radio-browser.info','nl1.api.radio-browser.info','at1.api.radio-browser.info'];
   let error='Radio directory unavailable';
   for(const host of hosts){try{
     const url=`https://${host}/json/stations/bycountrycodeexact/${country}?hidebroken=true&order=clickcount&reverse=true&limit=120`;
     const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),6500);
     let response;try{response=await fetch(url,{headers:{'User-Agent':'PingLahSG/1.0','Accept':'application/json'},signal:controller.signal})}finally{clearTimeout(timer)}
     if(!response.ok)throw Error('Directory HTTP '+response.status);
     const data=await response.json();if(!Array.isArray(data))throw Error('Invalid directory response');
     const seen=new Set();const stations=data.filter(x=>{const u=x.url_resolved||x.url||'';const name=(x.name||'').trim();const key=name.toLowerCase();if(!/^https:\/\//.test(u)||!name||seen.has(key)||x.lastcheckok===0)return false;seen.add(key);return true}).slice(0,45).map(x=>({name:x.name.trim(),url:x.url_resolved||x.url,homepage:x.homepage||'',bitrate:Number(x.bitrate)||0,tags:(x.tags||'').split(',').slice(0,3).join(', '),codec:x.codec||''}));
     return J({stations,country,source:'Radio Browser'});
   }catch(e){error=String(e.message||e)}}return J({error:'Could not reach radio directory: '+error},503)
 }

 if(!env.DB)return J({error:'Cloudflare D1 binding DB is required.'},503);
 const route='/'+(params.path||[]).join('/');const method=request.method;const data=async()=>{try{return await request.json()}catch{return {}}};
 const ip=request.headers.get('CF-Connecting-IP')||'unknown';
 const limited=async(key,max,windowMs)=>{const slot=Math.floor(now()/windowMs),k=key+':'+slot;await env.DB.prepare('INSERT INTO rate_limits(k,n,expires_at) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=n+1').bind(k,slot*windowMs+windowMs).run();const row=await env.DB.prepare('SELECT n FROM rate_limits WHERE k=?').bind(k).first();return row.n>max};
 if(route==='/recover'&&method==='POST'){if(await limited('recover:'+ip,8,3600000))return J({error:'Too many attempts. Try again later.'},429);const b=await data();const recovery=String(b.recovery||'').replace(/\s+/g,'').toUpperCase();if(recovery.length<20)return J({error:'Invalid recovery code'},400);const user=await env.DB.prepare('SELECT id,code,name FROM users WHERE recovery_hash=?').bind(await hash(recovery)).first();if(!user)return J({error:'Recovery code not found'},404);const newToken=uid()+uid(),newRecovery=Array.from(crypto.getRandomValues(new Uint8Array(24))).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();await env.DB.prepare('UPDATE users SET token_hash=?,recovery_hash=? WHERE id=?').bind(await hash(newToken),await hash(newRecovery),user.id).run();return J({token:newToken,recovery:newRecovery,me:user})}
 
 if(route==='/register'&&method==='POST'){if(await limited('register:'+ip,5,3600000))return J({error:'Too many registrations. Try again later.'},429);const b=await data(),name=String(b.name||'').trim().slice(0,60);if(!name)return J({error:'Enter a display name'},400);const token=uid()+uid();const recovery=Array.from(crypto.getRandomValues(new Uint8Array(24))).map(x=>x.toString(16).padStart(2,'0')).join('').toUpperCase();const id=uid();let c;for(let i=0;i<8;i++){c=code();try{await env.DB.prepare('INSERT INTO users(id,code,name,token_hash,recovery_hash,created_at) VALUES(?,?,?,?,?,?)').bind(id,c,name,await hash(token),await hash(recovery),now()).run();return J({token,recovery,me:{id,code:c,name}})}catch(e){if(!String(e).includes('UNIQUE'))throw e}}return J({error:'Please retry'},503)}
 const token=(request.headers.get('Authorization')||'').replace(/^Bearer /,'');if(!token)return J({error:'Sign in on this device first'},401);const me=await env.DB.prepare('SELECT id,code,name,status,status_message,last_seen,avatar FROM users WHERE token_hash=?').bind(await hash(token)).first();if(!me)return J({error:'Invalid session'},401);
 if(method==='POST'&&['/friends','/messages','/upload'].includes(route)&&await limited('write:'+me.id,90,3600000))return J({error:'Hourly sending limit reached.'},429);


 // Pocket Cam temporary private photos; requires MIGRATION-v37.sql.
 if(route.startsWith('/messenger/photo/')&&['GET','POST'].includes(method)){
  const id=route.split('/')[3];
  if(method==='POST'&&route.endsWith('/send'))return J({error:'Invalid photo route'},404);
  if(method==='POST'&&request.headers.get('content-type')?.includes('application/json')){
   const peer=id,linked=await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(me.id,peer).first();
   if(!linked)return J({error:'Not a connected friend'},403);
   if(await limited('photo:'+me.id,25,86400000))return J({error:'Daily photo limit reached (25)'},429);
   if(Number(request.headers.get('content-length')||0)>180000)return J({error:'Photo too large'},413);
   const b=await data(),image=String(b.image||'');
   if(!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(image)||image.length>150000||image.length<100)return J({error:'Invalid or oversized JPEG photo'},400);
   const bytes=atob(image.split(',')[1]);if(bytes.length>110000||bytes.charCodeAt(0)!==255||bytes.charCodeAt(1)!==216||bytes.charCodeAt(bytes.length-2)!==255||bytes.charCodeAt(bytes.length-1)!==217)return J({error:'Invalid JPEG data'},400);
   const id2=uid(),sent=now(),max=sent+7*86400000;
   await env.DB.batch([env.DB.prepare('INSERT INTO messenger_messages(id,sender_id,receiver_id,body,created_at) VALUES(?,?,?,?,?)').bind(id2,me.id,peer,'[Pocket Cam photo]',sent),env.DB.prepare('INSERT INTO pocket_photos(message_id,image_data,sent_at,max_expires_at) VALUES(?,?,?,?)').bind(id2,image,sent,max)]);
   return J({ok:true,id:id2});
  }
  const photo=await env.DB.prepare('SELECT p.image_data,p.sent_at,p.opened_at,p.max_expires_at,m.sender_id,m.receiver_id FROM pocket_photos p JOIN messenger_messages m ON m.id=p.message_id WHERE p.message_id=?').bind(id).first();
  if(!photo||![photo.sender_id,photo.receiver_id].includes(me.id))return J({error:'Photo unavailable'},404);
  const peer=photo.sender_id===me.id?photo.receiver_id:photo.sender_id;
  const linked=await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(me.id,peer).first();if(!linked)return J({error:'Not a connected friend'},403);
  const expiry=Math.min(photo.max_expires_at,photo.opened_at?photo.opened_at+43200000:photo.max_expires_at);
  if(now()>=expiry||!photo.image_data)return J({error:'Photo expired'},410);
  if(method==='GET'&&me.id===photo.receiver_id&&!photo.opened_at)return J({error:'Open the photo first'},403);
  if(method==='POST'&&me.id===photo.receiver_id&&!photo.opened_at){await env.DB.prepare('UPDATE pocket_photos SET opened_at=? WHERE message_id=? AND opened_at IS NULL').bind(now(),id).run();photo.opened_at=now()}
  return J({image:photo.image_data,expires_at:Math.min(photo.max_expires_at,photo.opened_at?photo.opened_at+43200000:photo.max_expires_at)});
 }

 if(route==='/push/public-key'&&method==='GET')return J({publicKey:env.VAPID_PUBLIC_KEY||null,configured:!!(env.VAPID_PUBLIC_KEY&&env.VAPID_PRIVATE_JWK)});
 if(route==='/push/subscribe'&&method==='POST'){
  if(!env.VAPID_PUBLIC_KEY||!env.VAPID_PRIVATE_JWK)return J({error:'Push is not configured in Cloudflare yet'},503);
  const b=await data(),sub=b.subscription||{},endpoint=String(sub.endpoint||''),p256dh=String(sub.keys?.p256dh||''),auth=String(sub.keys?.auth||'');
  if(endpoint.length>1200||!endpoint.startsWith('https://')||p256dh.length>150||auth.length>100||!p256dh||!auth)return J({error:'Invalid push subscription'},400);
  try{const host=new URL(endpoint).hostname;if(!/(^|\.)(push\.services\.mozilla\.com|fcm\.googleapis\.com|notify\.windows\.com|push\.apple\.com|web\.push\.apple\.com|push\.safari\.apple\.com)$/.test(host))return J({error:'Unsupported push service'},400)}catch{return J({error:'Invalid endpoint'},400)}
  await env.DB.prepare('INSERT INTO push_subscriptions(user_id,endpoint,p256dh,auth,created_at) VALUES(?,?,?,?,?) ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id,p256dh=excluded.p256dh,auth=excluded.auth').bind(me.id,endpoint,p256dh,auth,now()).run();return J({ok:true});
 }
 if(route==='/push/unsubscribe'&&method==='POST'){const b=await data();await env.DB.prepare('DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?').bind(me.id,String(b.endpoint||'')).run();return J({ok:true})}
 if(route==='/push/test'&&method==='POST'){
  if(await limited('push-test:'+me.id,5,3600000))return J({error:'Please wait before testing again'},429);
  const row=await env.DB.prepare('SELECT COUNT(*) AS n FROM push_subscriptions WHERE user_id=?').bind(me.id).first();
  if(!row?.n)return J({error:'Enable notifications on this device first'},400);
  const outcome=await pNotify(env,me.id,{title:'📟 Ping Lah! SG',body:'Test ping successful! Your pager is ready.',url:'/?open=pager',tag:'ping-test-'+now()});
  return J({ok:outcome.sent>0,...outcome},outcome.sent>0?200:502);
 }
 if(route==='/me'&&method==='GET'){await env.DB.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(now(),me.id).run();return J({me:{...me,last_seen:now()}})}
 if(route==='/me'&&method==='PATCH'){const b=await data();const name=String(b.name||'').trim().slice(0,60),status=String(b.status||me.status||'online'),status_message=String(b.status_message??me.status_message??'').trim().slice(0,120),avatar=String(b.avatar||me.avatar||'🙂');if(!name||!['🙂','😀','😎','🥳','🤓','😍','🥰','😴','😇','🤠','👻','👽','🤖','👾','💀','🎃','🐱','🐶','🦊','🐻','🐼','🐨','🐯','🦁','🐸','🐵','🐧','🐥','🦄','🐙','🦋','🐝','🐢','🦖','🌻','🌈','⭐','🌙','☀️','🔥','💖','💎','🎧','🎮','📼','💾','📟','📻','🎸','🍕','🍜','☕','⚽','🚀'].includes(avatar)||!['online','away','busy','brb','offline'].includes(status))return J({error:'Invalid profile'},400);await env.DB.prepare('UPDATE users SET name=?,status=?,status_message=?,avatar=? WHERE id=?').bind(name,status,status_message,avatar,me.id).run();return J({ok:true})}
 if(route==='/messenger/nudges'&&method==='GET'){const r=await env.DB.prepare('SELECT id,sender_id FROM messenger_nudges WHERE receiver_id=? AND seen_at IS NULL ORDER BY created_at DESC LIMIT 30').bind(me.id).all();const count=r.results.length;if(count)await env.DB.prepare('UPDATE messenger_nudges SET seen_at=? WHERE receiver_id=? AND seen_at IS NULL').bind(now(),me.id).run();return J({count,nudges:r.results});}
 if(route.startsWith('/messenger/nudge/')&&method==='POST'){const peer=route.split('/')[3];const linked=await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(me.id,peer).first();if(!linked)return J({error:'Not a connected friend'},403);if(await limited('nudge:'+me.id,12,3600000))return J({error:'Too many nudges. Try later.'},429);await env.DB.prepare('INSERT INTO messenger_nudges(id,sender_id,receiver_id,created_at) VALUES(?,?,?,?)').bind(uid(),me.id,peer,now()).run();return J({ok:true});}
 if(route==='/messenger/presence'&&method==='GET'){
  await env.DB.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(now(),me.id).run();
  const r=await env.DB.prepare('SELECT u.id,u.name,u.status,u.status_message,u.last_seen,u.avatar FROM friends f JOIN users u ON u.id=f.friend_id WHERE f.user_id=?').bind(me.id).all();
  return J({me:{...me,last_seen:now()},friends:r.results.map(x=>x.status==='offline'?{...x,last_seen:0}:x)});
 }
 if(route.startsWith('/messenger/typing/')&&['GET','POST'].includes(method)){
  const peer=route.split('/')[3];const linked=await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(me.id,peer).first();if(!linked)return J({error:'Not a connected friend'},403);
  if(method==='POST'){await env.DB.prepare('INSERT INTO messenger_typing(sender_id,receiver_id,updated_at) VALUES(?,?,?) ON CONFLICT(sender_id,receiver_id) DO UPDATE SET updated_at=excluded.updated_at').bind(me.id,peer,now()).run();return J({ok:true})}
  const state=await env.DB.prepare('SELECT updated_at FROM messenger_typing WHERE sender_id=? AND receiver_id=?').bind(peer,me.id).first();return J({typing:!!state&&now()-Number(state.updated_at)<5500});
 }
 if(route.startsWith('/messenger/chat/')&&['GET','POST'].includes(method)){
  const peer=route.split('/')[3];if(!peer)return J({error:'Friend required'},400);
  const linked=await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(me.id,peer).first();if(!linked)return J({error:'Not a connected friend'},403);
  if(method==='POST'){
   if(await limited('chat:'+me.id,120,3600000))return J({error:'Message limit reached. Try again later.'},429);
   const b=await data(),body=String(b.body||'').trim();if(!body||body.length>1000)return J({error:'Enter a message (maximum 1000 characters)'},400);
   const id=uid();await env.DB.prepare('INSERT INTO messenger_messages(id,sender_id,receiver_id,body,created_at) VALUES(?,?,?,?,?)').bind(id,me.id,peer,body,now()).run();
   const preview=body==='[Pocket Cam photo]'?'Sent you a Pocket Cam photo':body.slice(0,110);
   const alert={title:'Ping Lah! SG · Messenger',body:me.name+': '+preview,url:'/?open=messenger&friend='+encodeURIComponent(me.id),tag:'ping-messenger-'+id};
   const pushJob=pNotify(env,peer,alert).catch(e=>console.error('Messenger push:',e));
   if(context?.waitUntil)context.waitUntil(pushJob);else await pushJob;
   return J({ok:true,id});
  }
  const r=await env.DB.prepare('SELECT id,sender_id,receiver_id,body,created_at FROM messenger_messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) ORDER BY created_at DESC LIMIT 100').bind(me.id,peer,peer,me.id).all();
  const ms=r.results.reverse();const ids=ms.map(x=>x.id);let reactions=[];let photoMap={};if(ms.some(m=>m.body==='[Pocket Cam photo]')){const pids=ms.filter(m=>m.body==='[Pocket Cam photo]').map(m=>m.id);const pr=await env.DB.prepare('SELECT message_id,opened_at,max_expires_at,image_data FROM pocket_photos WHERE message_id IN ('+pids.map(()=>'?').join(',')+')').bind(...pids).all();photoMap=Object.fromEntries(pr.results.map(p=>[p.message_id,p]));} 
  if(ids.length){const q='SELECT message_id,emoji,COUNT(*) AS n FROM messenger_reactions WHERE message_id IN ('+ids.map(()=>'?').join(',')+') GROUP BY message_id,emoji';reactions=(await env.DB.prepare(q).bind(...ids).all()).results}
  return J({messages:ms.map(m=>({...m,...(m.body==='[Pocket Cam photo]'?{photo_opened_at:photoMap[m.id]?.opened_at||null,photo_expires_at:Math.min(photoMap[m.id]?.max_expires_at||0,photoMap[m.id]?.opened_at?photoMap[m.id].opened_at+43200000:photoMap[m.id]?.max_expires_at||0),photo_expired:!photoMap[m.id]?.image_data||now()>=Math.min(photoMap[m.id]?.max_expires_at||0,photoMap[m.id]?.opened_at?photoMap[m.id].opened_at+43200000:photoMap[m.id]?.max_expires_at||0)}:{}),reactions:Object.fromEntries(reactions.filter(x=>x.message_id===m.id).map(x=>[x.emoji,x.n]))}))});
 }
 if(route.startsWith('/messenger/react/')&&method==='POST'){
  const id=route.split('/')[3],b=await data(),emoji=String(b.emoji||'');if(!['❤️','😂','👍','😮','😢'].includes(emoji))return J({error:'Unsupported reaction'},400);
  const m=await env.DB.prepare('SELECT sender_id,receiver_id FROM messenger_messages WHERE id=?').bind(id).first();if(!m||![m.sender_id,m.receiver_id].includes(me.id))return J({error:'Message unavailable'},404);
  const peer=m.sender_id===me.id?m.receiver_id:m.sender_id;const linked=await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(me.id,peer).first();if(!linked)return J({error:'Not a connected friend'},403);
  const existing=await env.DB.prepare('SELECT emoji FROM messenger_reactions WHERE message_id=? AND user_id=?').bind(id,me.id).first();
  if(existing?.emoji===emoji)await env.DB.prepare('DELETE FROM messenger_reactions WHERE message_id=? AND user_id=?').bind(id,me.id).run();
  else await env.DB.prepare('INSERT INTO messenger_reactions(message_id,user_id,emoji) VALUES(?,?,?) ON CONFLICT(message_id,user_id) DO UPDATE SET emoji=excluded.emoji').bind(id,me.id,emoji).run();return J({ok:true});
 }
 if(route.startsWith('/friend-preview/')&&method==='GET'){if(await limited('preview:'+ip,120,3600000))return J({error:'Too many lookups'},429);const c=route.split('/')[2]?.toUpperCase()||'';if(!/^[A-HJ-NP-Z2-9]{8}$/.test(c))return J({error:'Invalid friend code'},400);const other=await env.DB.prepare('SELECT id,name,avatar FROM users WHERE code=?').bind(c).first();if(!other)return J({error:'Friend code not found'},404);const self=other.id===me.id;const exists=self?null:await env.DB.prepare('SELECT 1 AS found FROM friends WHERE user_id=? AND friend_id=?').bind(me.id,other.id).first();return J({name:other.name,avatar:other.avatar||'🙂',self,already:!!exists})}
 if(route==='/friends'&&method==='GET'){const r=await env.DB.prepare('SELECT u.id,u.code,u.name FROM friends f JOIN users u ON u.id=f.friend_id WHERE f.user_id=? ORDER BY u.name').bind(me.id).all();return J({friends:r.results})}
 if(route==='/friends'&&method==='POST'){const b=await data();const c=String(b.code||'').trim().toUpperCase();const other=await env.DB.prepare('SELECT id FROM users WHERE code=?').bind(c).first();if(!other)return J({error:'Friend code not found'},404);if(other.id===me.id)return J({error:'You cannot add yourself'},400);const t=now();await env.DB.batch([env.DB.prepare('INSERT OR IGNORE INTO friends VALUES(?,?,?)').bind(me.id,other.id,t),env.DB.prepare('INSERT OR IGNORE INTO friends VALUES(?,?,?)').bind(other.id,me.id,t)]);return J({ok:true})}
 if(route.startsWith('/friends/')&&method==='DELETE'){const fid=route.split('/')[2];await env.DB.batch([env.DB.prepare('DELETE FROM friends WHERE user_id=? AND friend_id=?').bind(me.id,fid),env.DB.prepare('DELETE FROM friends WHERE user_id=? AND friend_id=?').bind(fid,me.id)]);return J({ok:true})}
 if(route==='/messages'&&method==='GET'){await clean(env);const r=await env.DB.prepare('SELECT id,sender_id,receiver_id,kind,body,created_at,expires_at,read_at FROM messages WHERE sender_id=? OR receiver_id=? ORDER BY created_at DESC LIMIT 150').bind(me.id,me.id).all();return J({messages:r.results})}
 if(route==='/messages'&&method==='POST'){const b=await data(),to=String(b.to||''),kind=String(b.kind||'');if(!['page','voice'].includes(kind))return J({error:'Invalid type'},400);const linked=await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(me.id,to).first();if(!linked)return J({error:'Not a connected friend'},403);let body=null,key=null;const t=now(),id=uid();if(kind==='page'){body=String(b.body||'').trim().slice(0,200);if(!body)return J({error:'Choose a message'},400)}else{key=String(b.key||'');if(!key.startsWith(me.id+'/')||!(/\.(webm|mp4|ogg)$/.test(key)))return J({error:'Upload audio first'},400);if(!await env.DB.prepare('SELECT 1 FROM voice_blobs WHERE id=? AND owner_id=?').bind(key,me.id).first())return J({error:'Recording not found'},400)}await env.DB.prepare('INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,NULL)').bind(id,me.id,to,kind,body,key,t,t+(kind==='page'?7:1)*86400000).run();
 const alert={title:kind==='page'?'Ping Lah! SG · Pager':'Ping Lah! SG · Walkie-Talkie',body:kind==='page'?me.name+' paged you: '+body:me.name+' sent you a voice transmission',url:kind==='page'?'/?open=pager&friend='+encodeURIComponent(me.id):'/?open=walkie&friend='+encodeURIComponent(me.id),tag:'ping-'+id};
 const job=pNotify(env,to,alert).catch(e=>console.error('Push delivery:',e));
 if(context?.waitUntil)context.waitUntil(job);else await job;
 return J({ok:true,id})}
 if(route==='/upload'&&method==='POST'){const type=request.headers.get('content-type')||'';if(!/^audio\/(webm|mp4|ogg)/.test(type))return J({error:'Unsupported audio format'},415);const blob=await request.arrayBuffer();if(blob.byteLength>380_000||blob.byteLength<100)return J({error:'Recording too large or empty (380KB max). Please use a shorter recording.'},413);const ext=type.includes('mp4')?'mp4':type.includes('ogg')?'ogg':'webm';const key=me.id+'/'+uid()+'.'+ext;const bytes=new Uint8Array(blob);let binary='';for(let i=0;i<bytes.length;i+=8192)binary+=String.fromCharCode(...bytes.subarray(i,i+8192));const base64=btoa(binary);await env.DB.prepare('INSERT INTO voice_blobs(id,owner_id,data_base64,mime,expires_at) VALUES(?,?,?,?,?)').bind(key,me.id,base64,type.split(';')[0],now()+86400000).run();return J({key})}
 if(route.startsWith('/audio/')&&method==='GET'){const id=route.split('/')[2];const m=await env.DB.prepare('SELECT * FROM messages WHERE id=? AND expires_at>?').bind(id,now()).first();if(!m||m.kind!=='voice'||![m.sender_id,m.receiver_id].includes(me.id))return J({error:'Recording unavailable'},404);const obj=await env.DB.prepare('SELECT data_base64,mime FROM voice_blobs WHERE id=? AND expires_at>?').bind(m.object_key,now()).first();if(!obj)return J({error:'Recording expired'},404);const bin=atob(obj.data_base64),bytes=Uint8Array.from(bin,c=>c.charCodeAt(0));return new Response(bytes,{headers:{'content-type':obj.mime,'cache-control':'no-store'}})}
 if(route.startsWith('/read/')&&method==='POST'){await env.DB.prepare('UPDATE messages SET read_at=? WHERE id=? AND receiver_id=?').bind(now(),route.split('/')[2],me.id).run();return J({ok:true})}
 return J({error:'Unknown endpoint'},404)
 }catch(e){console.error(e);return J({error:'Server request failed. Check D1 schema and Cloudflare bindings.'},500)}}

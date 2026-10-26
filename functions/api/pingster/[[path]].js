const json=(x,s=200)=>new Response(JSON.stringify(x),{status:s,headers:{'content-type':'application/json','cache-control':'no-store'}});
const hash=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))).map(x=>x.toString(16).padStart(2,'0')).join('');
const t=()=>Date.now(),id=()=>crypto.randomUUID();
export async function onRequest({request,env,params}){try{
 if(!env.DB)return json({error:'D1 DB binding missing'},503);
 const db=env.DB,route='/'+(params.path||[]).join('/'),method=request.method;
 const bearer=(request.headers.get('authorization')||'').replace(/^Bearer /i,'');
 if(!bearer)return json({error:'Please sign in to Ping Lah! first'},401);
 const me=await db.prepare('SELECT id,name FROM users WHERE token_hash=?').bind(await hash(bearer)).first();
 if(!me)return json({error:'Session expired'},401);
 const body=async()=>{try{return await request.json()}catch{return {}}};
 const q=new URL(request.url).searchParams;
 const friend=async user=>{if(user===me.id)return true;const f=await db.prepare('SELECT 1 FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?) LIMIT 1').bind(me.id,user,user,me.id).first();return !!f};
 const see=async user=>{if(!(await friend(user)))throw Error('Friends-only profile')};
 const notify=async(to,kind,post,actor)=>{if(to===actor)return;await db.prepare('INSERT INTO pingster_notifications(id,user_id,actor_id,kind,post_id,created_at) VALUES(?,?,?,?,?,?)').bind(id(),to,actor,kind,post,t()).run()};
 if(route==='/home'&&method==='GET'){
  const people=await db.prepare('SELECT u.id,u.name,p.avatar_photo_id FROM users u LEFT JOIN pingster_profiles p ON p.user_id=u.id WHERE u.id=? OR u.id IN (SELECT friend_id FROM friends WHERE user_id=?) OR u.id IN (SELECT user_id FROM friends WHERE friend_id=?) ORDER BY u.name LIMIT 120').bind(me.id,me.id,me.id).all();
  const notifications=await db.prepare('SELECT COUNT(*) AS n FROM pingster_notifications WHERE user_id=? AND read_at IS NULL').bind(me.id).first();
  return json({me,people:people.results||[],unread:notifications?.n||0});
 }
 if(route==='/profile'&&method==='GET'){
  const user=q.get('user')||me.id;await see(user);
  const row=await db.prepare('SELECT u.id,u.name,p.bio,p.birthday,p.food,p.country,p.movies,p.songs,p.hobbies,p.motto,p.theme,p.colour,p.avatar_photo_id FROM users u LEFT JOIN pingster_profiles p ON p.user_id=u.id WHERE u.id=?').bind(user).first();
  if(!row)return json({error:'Profile unavailable'},404);
  return json({profile:row,own:user===me.id});
 }
 if(route==='/profile'&&method==='POST'){
  const b=await body(),fields=['bio','birthday','food','country','movies','songs','hobbies','motto'];
  const v=fields.map(k=>String(b[k]||'').trim().slice(0,k==='bio'?300:120));
  const theme=['classic','friendster'].includes(b.theme)?b.theme:'classic';const colour=['pink','purple','mint','orange','blue'].includes(b.colour)?b.colour:'pink';
  await db.prepare('INSERT INTO pingster_profiles(user_id,bio,birthday,food,country,movies,songs,hobbies,motto,theme,colour) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET bio=excluded.bio,birthday=excluded.birthday,food=excluded.food,country=excluded.country,movies=excluded.movies,songs=excluded.songs,hobbies=excluded.hobbies,motto=excluded.motto,theme=excluded.theme,colour=excluded.colour').bind(me.id,...v,theme,colour).run();return json({ok:true});
 }
 if(route==='/space'&&method==='GET'){
  // Friends-only timeline: a post is visible only if its wall owner is the viewer or an accepted friend.
  const before=Number(q.get('before')||0);
  const cursor=Number.isSafeInteger(before)&&before>0?before:Date.now()+1;
  const rows=await db.prepare(`SELECT p.id,p.owner_id,p.author_id,p.body,p.photo_id,p.radio_name,p.radio_url,p.created_at,
   u.name AS author_name, wall.name AS owner_name, pic.avatar_photo_id AS author_avatar_id,
   (SELECT COUNT(*) FROM pingster_likes l WHERE l.post_id=p.id) AS likes,
   (SELECT COUNT(*) FROM pingster_comments c WHERE c.post_id=p.id) AS comments,
   (SELECT COUNT(*) FROM pingster_likes l WHERE l.post_id=p.id AND l.user_id=?) AS liked
   FROM pingster_posts p JOIN users u ON u.id=p.author_id JOIN users wall ON wall.id=p.owner_id
   LEFT JOIN pingster_profiles pic ON pic.user_id=p.author_id
   WHERE p.created_at < ? AND (p.owner_id=? OR EXISTS
    (SELECT 1 FROM friends f WHERE (f.user_id=? AND f.friend_id=p.owner_id) OR (f.friend_id=? AND f.user_id=p.owner_id)))
   ORDER BY p.created_at DESC,p.id DESC LIMIT 21`).bind(me.id,cursor,me.id,me.id,me.id).all();
  const all=rows.results||[];const more=all.length>20;const posts=all.slice(0,20);
  return json({posts,more,next:more&&posts.length?posts[posts.length-1].created_at:null});
 }
 if(route==='/posts'&&method==='GET'){
  const user=q.get('user')||me.id;await see(user);
  const rows=await db.prepare(`SELECT p.id,p.owner_id,p.author_id,p.body,p.photo_id,p.radio_name,p.radio_url,p.created_at,u.name AS author_name,(SELECT COUNT(*) FROM pingster_likes l WHERE l.post_id=p.id) AS likes,(SELECT COUNT(*) FROM pingster_comments c WHERE c.post_id=p.id) AS comments,(SELECT COUNT(*) FROM pingster_likes l WHERE l.post_id=p.id AND l.user_id=?) AS liked FROM pingster_posts p JOIN users u ON u.id=p.author_id WHERE p.owner_id=? ORDER BY p.created_at DESC LIMIT 60`).bind(me.id,user).all();return json({posts:rows.results||[]});
 }
 if(route==='/posts'&&method==='POST'){
  const b=await body(),owner=String(b.owner||me.id);await see(owner);
  const msg=String(b.body||'').trim().slice(0,1000),photo=String(b.photo_id||'');let station='',url='';
  if(b.radio_name&&b.radio_url){station=String(b.radio_name).slice(0,120);url=String(b.radio_url);if(!/^https:\/\//i.test(url)||url.length>700)return json({error:'Invalid radio link'},400)}
  if(!msg&&!photo&&!station)return json({error:'Write something or attach a Pocket Cam photo'},400);
  if(photo){const p=await db.prepare('SELECT id FROM pingster_photos WHERE id=? AND owner_id=?').bind(photo,me.id).first();if(!p)return json({error:'Pocket Cam photo not found'},400)}
  const post=id();await db.prepare('INSERT INTO pingster_posts(id,owner_id,author_id,body,photo_id,radio_name,radio_url,created_at) VALUES(?,?,?,?,?,?,?,?)').bind(post,owner,me.id,msg,photo||null,station||null,url||null,t()).run();await notify(owner,'wall',post,me.id);return json({ok:true,id:post});
 }
 const postId=route.match(/^\/posts\/([a-f0-9-]+)$/)?.[1];
 if(postId&&method==='DELETE'){
  const p=await db.prepare('SELECT owner_id,author_id FROM pingster_posts WHERE id=?').bind(postId).first();if(!p||![p.owner_id,p.author_id].includes(me.id))return json({error:'Not permitted'},403);
  await db.prepare('DELETE FROM pingster_comments WHERE post_id=?').bind(postId).run();await db.prepare('DELETE FROM pingster_likes WHERE post_id=?').bind(postId).run();await db.prepare('DELETE FROM pingster_notifications WHERE post_id=?').bind(postId).run();await db.prepare('DELETE FROM pingster_posts WHERE id=?').bind(postId).run();return json({ok:true});
 }
 const like=route.match(/^\/posts\/([a-f0-9-]+)\/like$/)?.[1];
 if(like&&method==='POST'){
  const p=await db.prepare('SELECT owner_id,author_id FROM pingster_posts WHERE id=?').bind(like).first();if(!p)return json({error:'Post not found'},404);await see(p.owner_id);
  const existing=await db.prepare('SELECT 1 FROM pingster_likes WHERE post_id=? AND user_id=?').bind(like,me.id).first();
  if(existing)await db.prepare('DELETE FROM pingster_likes WHERE post_id=? AND user_id=?').bind(like,me.id).run();else{await db.prepare('INSERT INTO pingster_likes(post_id,user_id) VALUES(?,?)').bind(like,me.id).run();await notify(p.author_id,'like',like,me.id)}return json({liked:!existing});
 }
 const comment=route.match(/^\/posts\/([a-f0-9-]+)\/comments$/)?.[1];
 if(comment){const p=await db.prepare('SELECT owner_id,author_id FROM pingster_posts WHERE id=?').bind(comment).first();if(!p)return json({error:'Post not found'},404);await see(p.owner_id);
  if(method==='GET'){const r=await db.prepare('SELECT c.id,c.body,c.created_at,c.author_id,u.name FROM pingster_comments c JOIN users u ON u.id=c.author_id WHERE c.post_id=? ORDER BY c.created_at LIMIT 100').bind(comment).all();return json({comments:r.results||[]})}
  if(method==='POST'){const b=await body(),msg=String(b.body||'').trim().slice(0,500);if(!msg)return json({error:'Comment cannot be empty'},400);await db.prepare('INSERT INTO pingster_comments(id,post_id,author_id,body,created_at) VALUES(?,?,?,?,?)').bind(id(),comment,me.id,msg,t()).run();await notify(p.author_id,'comment',comment,me.id);return json({ok:true})}
 }
 if(route==='/notifications'&&method==='GET'){
  const r=await db.prepare('SELECT n.id,n.kind,n.post_id,n.created_at,n.read_at,u.name AS actor_name FROM pingster_notifications n JOIN users u ON u.id=n.actor_id WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 100').bind(me.id).all();return json({notifications:r.results||[]});
 }
 if(route==='/notifications/read'&&method==='POST'){const b=await body();if(b.id)await db.prepare('UPDATE pingster_notifications SET read_at=? WHERE id=? AND user_id=?').bind(t(),String(b.id),me.id).run();else await db.prepare('UPDATE pingster_notifications SET read_at=? WHERE user_id=? AND read_at IS NULL').bind(t(),me.id).run();return json({ok:true})}
 if(route==='/photo'&&method==='POST'){
  const b=await body(),avatar=!!b.avatar,raw=String(b.image||'');if(!/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(raw))return json({error:'Only Pocket Cam JPEG captures accepted'},400);
  const bytes=Uint8Array.from(atob(raw.split(',')[1]),c=>c.charCodeAt(0));const limit=avatar?15360:40960;
  if(bytes.length>limit)return json({error:'Photo exceeds '+Math.floor(limit/1024)+' KB limit'},413);
  if(bytes[0]!==255||bytes[1]!==216)return json({error:'Invalid JPEG'},400);
  const count=await db.prepare('SELECT COUNT(*) AS n FROM pingster_photos WHERE owner_id=? AND is_avatar=0').bind(me.id).first();if(!avatar&&count.n>=30)return json({error:'30-photo Memory Card is full'},409);
  const photo=id();await db.prepare('INSERT INTO pingster_photos(id,owner_id,image,is_avatar,created_at) VALUES(?,?,?,?,?)').bind(photo,me.id,bytes,avatar?1:0,t()).run();
  if(avatar){await db.prepare('INSERT INTO pingster_profiles(user_id,avatar_photo_id) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET avatar_photo_id=excluded.avatar_photo_id').bind(me.id,photo).run();await db.prepare('DELETE FROM pingster_photos WHERE owner_id=? AND is_avatar=1 AND id<>?').bind(me.id,photo).run()}
  return json({id:photo});
 }
 const image=route.match(/^\/photo\/([a-f0-9-]+)$/)?.[1];
 if(image&&method==='GET'){
  const row=await db.prepare('SELECT owner_id,image FROM pingster_photos WHERE id=?').bind(image).first();if(!row)return json({error:'Photo unavailable'},404);
  if(!(await friend(row.owner_id))){const shared=await db.prepare('SELECT owner_id FROM pingster_posts WHERE photo_id=?').bind(image).first();if(!shared||!(await friend(shared.owner_id)))return json({error:'Friends only'},403)}
  const stored=row.image;const photoBytes=stored instanceof ArrayBuffer?new Uint8Array(stored):stored instanceof Uint8Array?stored:Array.isArray(stored)?new Uint8Array(stored):stored&&stored.type==='Buffer'&&Array.isArray(stored.data)?new Uint8Array(stored.data):null;
  if(!photoBytes||photoBytes.length<4||photoBytes[0]!==255||photoBytes[1]!==216)return json({error:'Photo data could not be decoded'},500);
  return new Response(photoBytes,{headers:{'content-type':'image/jpeg','cache-control':'private,max-age=120','x-content-type-options':'nosniff'}});
 }
 return json({error:'Unknown Pingster endpoint'},404);
 }catch(e){return json({error:String(e.message||e)},500)}}

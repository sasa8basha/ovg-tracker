"""
interstitial_template.py — HTML for /go/{campaign_key} (Phase 1.3)

صفحة سريعة جداً (~4KB) — بتحمل، تجمع بصمة، تبعتها، تستقبل القرار، redirect.
Max time: 800ms ثم redirect anyway (safety).
"""

INTERSTITIAL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="robots" content="noindex,nofollow">
<title>Loading</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%;width:100%;overflow:hidden;background:#f8f9fa;color:#6c757d;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}
#r{display:flex;align-items:center;justify-content:center;height:100%;flex-direction:column;gap:16px;padding:16px;text-align:center}
.sp{width:36px;height:36px;border:3px solid rgba(108,117,125,.15);border-top-color:#6c757d;border-radius:50%;animation:r .9s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
.m{font-size:13px;opacity:.6}
</style>
</head>
<body>
<div id="r">
  <div class="sp"></div>
  <div class="m" id="msg">Loading...</div>
</div>
<script>
(function(){
"use strict";
var CK='__CAMPAIGN_KEY__';
var DU='__DEST_URL__';
var PU='__PRECHECK_URL__';
var LU='__LOG_URL__';
var MT=800;
var sid='';
var t0=Date.now();

function uuid(){
try{if(crypto.randomUUID)return crypto.randomUUID();}catch(e){}
var s='';for(var i=0;i<32;i++)s+=(Math.random()*16|0).toString(16);
return s.substr(0,8)+'-'+s.substr(8,4)+'-'+s.substr(12,4)+'-'+s.substr(16,4)+'-'+s.substr(20,12);
}
sid=uuid();

function ga(){
var o={puppeteer:false,playwright:false,selenium:false,nightmare:false,phantom:false,cdc:false};
try{
if(window.__puppeteer_evaluation_script__!==undefined)o.puppeteer=true;
if(window.__playwright__!==undefined||window.__playwright_evaluation_script__!==undefined)o.playwright=true;
if(window.__nightmare!==undefined)o.nightmare=true;
if(window.callPhantom!==undefined||window._phantom!==undefined)o.phantom=true;
var ks=Object.keys(window);
for(var i=0;i<ks.length;i++){
var k=ks[i];
if(k.indexOf('$cdc_')===0||k.indexOf('cdc_')===0){o.cdc=true;o.selenium=true;break;}
if(k==='_Selenium_IDE_Recorder'||k==='_selenium'||k==='calledSelenium'){o.selenium=true;break;}
}
}catch(e){}
return o;
}

function gc(){
try{
var d=false;
var err=new Error();
Object.defineProperty(err,'stack',{get:function(){d=true;return'';}});
if(typeof console!=='undefined'&&console.debug)console.debug(err);
return d;
}catch(e){return false;}
}

function gcv(){
try{
var c=document.createElement('canvas');c.width=220;c.height=40;
var x=c.getContext('2d');if(!x)return 'blocked';
x.textBaseline='top';x.font='15px Arial';
x.fillStyle='#f60';x.fillRect(120,1,62,20);
x.fillStyle='#069';x.fillText('OVG-i3',2,15);
x.fillStyle='rgba(102,204,0,0.7)';x.fillText('OVG-i3',4,17);
var d=c.toDataURL();var h=5381;
for(var i=0;i<d.length;i++)h=((h<<5)+h+d.charCodeAt(i))|0;
return 'fp_'+Math.abs(h).toString(16);
}catch(e){return 'blocked';}
}

function gtz(){
try{return Intl.DateTimeFormat().resolvedOptions().timeZone||'';}catch(e){return'';}
}

function buildPayload(){
var qs='';
try{qs=location.search||'';}catch(e){}
return {
v:3,
session_id:sid,
campaign_key:CK,
t_ms:Date.now()-t0,
url:qs,
nav:{
ua:navigator.userAgent||'',
platform:navigator.platform||'',
webdriver:navigator.webdriver===true,
language:navigator.language||'',
has_touch:('ontouchstart' in window)||(navigator.maxTouchPoints>0),
max_touch_points:Number(navigator.maxTouchPoints)||0
},
fp:{
automation:ga(),
cdp_detected:gc(),
canvas_hash:gcv(),
timezone:gtz(),
languages:(function(){try{var l=navigator.languages;var a=[];if(l)for(var i=0;i<l.length&&i<3;i++)a.push(String(l[i]));return a;}catch(e){return[];}})(),
ua_data:(function(){try{if(navigator.userAgentData)return{mobile:navigator.userAgentData.mobile===true,platform:String(navigator.userAgentData.platform||'')};}catch(e){}return null;})()
}
};
}

function log(decision,score,reasons){
try{
var p={
v:3,
session_id:sid,
campaign_key:CK,
decision:decision,
score:score||0,
reasons:reasons||[],
t_ms:Date.now()-t0,
url:location.search||''
};
var blob=new Blob([JSON.stringify(p)],{type:'application/json'});
if(navigator.sendBeacon){navigator.sendBeacon(LU,blob);}
}catch(e){}
}

var done=false;
function finish(decision,url,score,reasons){
if(done)return;
done=true;
log(decision,score,reasons);
if(decision==='redirect'&&url&&url.length>5){
try{window.location.replace(url);}catch(e){}
}else{
var m=document.getElementById('msg');
if(m)m.textContent='';
}
}

var safety=setTimeout(function(){
finish('timeout',DU,0,[]);
},MT+300);

try{
var body=JSON.stringify(buildPayload());
fetch(PU,{
method:'POST',
headers:{'Content-Type':'application/json'},
body:body,
credentials:'omit',
keepalive:true
}).then(function(r){return r.json().catch(function(){return{};});}).then(function(d){
clearTimeout(safety);
if(d&&d.action==='block'){
finish('block','',d.score||100,d.reasons||[]);
}else if(d&&d.url){
finish('redirect',d.url,d.score||0,d.reasons||[]);
}else{
finish('fallback',DU,0,[]);
}
}).catch(function(){
clearTimeout(safety);
finish('error',DU,0,[]);
});
}catch(e){
clearTimeout(safety);
finish('error',DU,0,[]);
}
})();
</script>
</body>
</html>"""

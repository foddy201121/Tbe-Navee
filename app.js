// NAVEE XT5 Unlock - standalone Web Bluetooth. All BLE stays local; no server, no tracking.
// Reverse-engineered from the official app (com.navee.ucaret, com.uz.navee.ble.*).
//
// Verified byte-for-byte against the decompiled app v2.1.6 (versionCode 110).
// (The repo previously referenced v2.1.5; keys, frame format and auth are unchanged in 2.1.6.)
//
// Protocol (confirmed from decompiled BleHandler / ByteUtil in v2.1.6):
//   GATT service 0000d0ff-3c17-d293-8e48-14fe2e4da212, WRITE 0000b002, NOTIFY 0000b003
//   Frame READ : 55 AA <flag> <cmd> <cksum> FE FD                       (BleHandler.j)
//   Frame WRITE: 55 AA <flag> <cmd> <len> <payload...> <cksum> FE FD    (BleHandler.k/l)
//   flag byte is 0x00 for all app reads/writes; cksum = (sum of every byte from 0x55
//   through the last payload byte) & 0xFF (BleHandler.d0).
//   RX  frame : 55 AA <flag> <cmd> <len> <ERRCODE> <data...> <cksum> FE FD
//     IMPORTANT: on receive, byte[5] is an ERROR/STATUS code (0 = ok). The data block the
//     app decodes starts at byte[6]. <len> counts errcode + data. (BleHandler.G, line ~260)
//   Auth = challenge/response (byte-exact, unchanged):
//     TX 0x30  55 AA 00 30 09 <keyIdx> <shareFlag> <s(userId)=88 + 48bitBE, 6B> 00 <cksum> FE FD
//              lead byte is 0x88 (TsExtractor.TS_STREAM_TYPE_DTS_HD=136), NOT 0x8A - ByteUtil.s
//     RX 0x30  scooter returns a 16-byte challenge (data block)
//     TX 0x31  55 AA 00 31 10 <AES-128-ECB-encrypt(challenge, keys[keyIdx])> <cksum> FE FD
//     RX 0x31  errcode 0 => authenticated
//   ByteUtil.j = AES/ECB/NoPadding, Cipher ENCRYPT (mode 1) -> the response IS an encryption.
//
// Speed levers (all verified in v2.1.6, sent via BleHandler.k/l from the app's own screens):
//   0x6B (107) custom speed limit  : 55 AA 00 6B 01 <val> ...   val = kmh & 0x7F, bit7 = limit-on
//                                    (SpeedLimitActivity -> sendCmd 107)
//   0x6E (110) max speed / mode    : 55 AA 00 6E 02 01 <val> ... subcmd 01 = set max speed = <val> kmh
//                                    (MaxSpeedActivity -> sendCmd 110 {1, val})
//   0x6A (106) startup speed       : 55 AA 00 6A 01 <val> ...   (StartupSpeedActivity -> sendCmd 106)
//   0x6F (111) scooter params      : subcmd 08 = region/country (persistent SKU), subcmd 06 = time
//                                    (BleHandlerDevicePort CountryConfig / BleHandler time sync)
//   For an XT5 (PID prefix 2782) the app itself offers max speed up to 32 km/h. Values beyond that
//   are not exercised by the app and depend on what the firmware accepts (hardware test).
const BUILD = 'v55';
// A bound XT5 only authenticates the account it was bound to: the 0x30 init carries the numeric
// account userId (ByteUtil.s), and the scooter answers a wrong id with errcode 0xFF *before* any
// challenge (verified against the decompile + a real device log). A random id only works on an
// UNBOUND scooter (trust-on-first-use). So the real numeric userId must be supplied for a bound one.
// crypto-strong random in [0,max) - keeps Math.random() out of the auth path (CodeQL: insecure randomness)
function secRandInt(max){ const a=new Uint32Array(1); (self.crypto||self.msCrypto).getRandomValues(a); return a[0] % max; }
const AUTO_UID = secRandInt(1000000000)+1;   // fallback for an unbound scooter only
const SERVICE     = '0000d0ff-3c17-d293-8e48-14fe2e4da212';
const WRITE_CHAR  = '0000b002-0000-1000-8000-00805f9b34fb';
const NOTIFY_CHAR = '0000b003-0000-1000-8000-00805f9b34fb';

const CMD = {
  AUTH_INIT:0x30, AUTH_RESP:0x31,
  START_SPEED:0x6A, LIMIT_SPEED:0x6B, MAX_SPEED:0x6E,   // direct speed levers
  REGION:0x6F,                                          // scooter params (subcmd 08 = country)
  READ_PARAMS:0x70, REPORT:0x70,                        // read/report full vehicle param block
  READ_BATTERY:0x72,                                    // (was mislabelled READ_SN in the old build)
  READ_FW:0x73,
  READ_SN:0x74, SN_REPORT:0x74,                         // read/report car serial (region source)
};

// 5 built-in AES-128 keys (BleHandler.f19454l) - byte-for-byte identical in v2.1.6.
const KEYS = [
  [0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF],
  [0x44,0x6D,0x10,0x72,0x6D,0xBE,0x05,0xF6,0x62,0xDF,0xAA,0xF0,0x13,0x27,0x30,0x3F],
  [0xA2,0x85,0xCC,0xEC,0x81,0x4F,0xE9,0x61,0x74,0x29,0x95,0xE8,0xEB,0xA9,0x22,0x47],
  [0x3F,0xEE,0x80,0xFF,0x96,0xDF,0x5C,0xF5,0x42,0xEA,0xAC,0x93,0x28,0x1F,0xE5,0x29],
  [0x4E,0xB4,0xD4,0x64,0xD6,0xEF,0x53,0xED,0x6C,0xE9,0x45,0x58,0xDE,0x9A,0x5E,0xE3],
].map(a => new Uint8Array(a));

// Region -> SKU (BleHandler.a0), AreaCode derived read-only from serial[8:10]
function skuOf(area){ return ['IT','DE','NE'].includes(area) ? 'ITA' : ['US','CN','RU'].includes(area) ? 'USA' : 'EUR'; }

// Model detection: NAVEE serials are [FAMILY LETTER E/T/U/V/W][4-digit pid at index 1..4]...[region 8..9].
// Confirmed line-by-line on the XT5/GT3/S meters; real sibling serial "T24435AVDE4C00328" -> pid 2443 = XT5 Ultra.
// Map: pid-prefix -> [modelName, cruiseSettable, kickSettable]. 1 = yes, 0 = no (firmware), null = unverified.
// Values come from the full fleet firmware sweep (meter read line-by-line, controller cross-checked).
// Speed is intentionally omitted here - it stays parked until the fleet speed-lever hunt is fully verified.
const MODELS = {
  '2213':['N65i',null,null], '2314':['V25/V25i',null,null], '2322':['S40',1,0],
  '2326':['V3 Pro',null,null], '2327':['V25 Pro/V25i Pro',null,null], '2328':['V40i/V40i Pro',null,null],
  '2329':['V50i Pro',0,0], '2334':['S60',1,0], '2345':['ST3 Pro',1,1], '2353':['P50',null,null],
  '2401':['ST3',1,1], '2402':['GT3',1,1], '2403':['GT3 Pro',1,1], '2416':['XT5 Pro',1,1],
  '2417':['E20',1,0], '2418':['GT3 Max',1,1], '2422':['E25',1,0], '2435':['Birdie 3',0,0],
  '2436':['V25i Pro II',0,0], '2437':['V40i Pro II',1,0], '2438':['V50i Pro II',0,0], '2441':['ST5 Pro',1,1],
  '2442':['G5',1,1], '2443':['XT5 Ultra',1,1], '2449':['NT5 Ultra X',1,1], '2504':['K100',null,null],
  '2505':['K100 Pro',null,null], '2506':['K100 Max',1,1], '2509':['N65i II',1,1], '2515':['Birdie 3x',0,0],
  '2517':['ST5 Max',1,1], '2518':['G5 pro',1,1], '2519':['G5 Max',1,1], '2529':['XT5 Max',1,1],
  '2536':['S2',1,1], '2538':['UT5 Max',1,1], '2543':['NT5 Max',1,1], '2545':['GT5 Pro',1,1],
  '2546':['GT5 Max',1,1], '2547':['UT5 Ultra',null,null], '2573':['E25 Go',1,1], '2585':['UT5 Ultra X',1,1],
  '2611':['E45 Pro',1,1], '2612':['E60 Pro',1,1], '2614':['S2',1,1], '2619':['UT3 Pro',null,null],
  '2620':['UT3 Max',1,1], '2623':['V45i',null,null], '2634':['E20 Lite',1,1], '2643':['E60 Pro',1,1],
  '2646':['UT3',null,null], '2657':['NT5 Max+',1,1], '2658':['NT5 Ultra',1,1], '2701':['NT3 Pro',1,1],
  '2704':['GT3 Pro',1,1], '2707':['NT5 Turbo',1,1], '2714':['ST3 Pro',1,1], '2736':['KG05',null,null],
  '2739':['WOLF X',null,null], '2745':['NT3 Max',1,1], '2753':['E45 Pro',1,1], '2754':['E60 Pro',1,1],
  '2768':['EXO S Pro',0,0],
};
// Pull the 4-digit pid out of a serial string: skip a leading family letter, take the next 4 digits.
function pidOf(sn){ if(!sn) return null; const m=String(sn).match(/[A-Za-z]?(\d{4})/); return m?m[1]:null; }

// Speed lever per pid-prefix - ONLY the four families where the flash-free BLE gear/mode lever is
// proven end-to-end (meter + controller) and adversarially verified. Value = [deHint, enHint] shown
// verbatim under the unlock button. The lever is gear-4 / top gear (0x58=4); the firmware clamps the
// result to the unit's own SKU/region, so the achieved km/h is a range, not a settable number.
const SPEED = {
  '2443':['XT5 Ultra: 40,5 bis 50,8 km/h je nach SKU des Geräts. Die 50,8 sind im Code belegt, aber nicht per Messfahrt bestätigt.',
          'XT5 Ultra: 40.5 to 50.8 km/h depending on the unit SKU. The 50.8 is code-proven but not confirmed by a measured ride.'],
  '2416':['XT5 Pro: rund 50 km/h (SKU 8 bis etwa 65), abhängig von der internen Gang-Zuordnung.',
          'XT5 Pro: about 50 km/h (SKU 8 up to ~65), depending on the internal gear mapping.'],
  '2529':['XT5 Max: rund 50 km/h (SKU 8 bis etwa 65), abhängig von der internen Gang-Zuordnung.',
          'XT5 Max: about 50 km/h (SKU 8 up to ~65), depending on the internal gear mapping.'],
  '2585':['UT5 Ultra X: bis 60 km/h auf unbeschränkter SKU. Die 70 aus der App sind nicht belegt.',
          'UT5 Ultra X: up to 60 km/h on an unrestricted SKU. The 70 the app offers is not proven.'],
  '2611':['E45 Pro: bis etwa 32,5 km/h auf freizügiger Region, sonst region-gedrosselt.',
          'E45 Pro: up to about 32.5 km/h on a permissive region, otherwise region-limited.'],
  '2753':['E45 Pro: bis etwa 32,5 km/h auf freizügiger Region, sonst region-gedrosselt.',
          'E45 Pro: up to about 32.5 km/h on a permissive region, otherwise region-limited.'],
  '2612':['E60 Pro: bis etwa 32,5 km/h auf freizügiger Region, sonst region-gedrosselt.',
          'E60 Pro: up to about 32.5 km/h on a permissive region, otherwise region-limited.'],
  '2643':['E60 Pro: bis etwa 32,5 km/h auf freizügiger Region, sonst region-gedrosselt.',
          'E60 Pro: up to about 32.5 km/h on a permissive region, otherwise region-limited.'],
  '2754':['E60 Pro: bis etwa 32,5 km/h auf freizügiger Region, sonst region-gedrosselt.',
          'E60 Pro: up to about 32.5 km/h on a permissive region, otherwise region-limited.'],
};
let detectedModel=null, detectedCaps=null, detectedSpeed=null, detectedSku=null, detectedBldcFw=null;   // detectedCaps = [name, cruise, kick]; detectedSpeed = [deHint, enHint] or null; detectedSku = EUR/ITA/USA; detectedBldcFw = controller version string
// A scooter flashed with our latch firmware reports a distinct controller version: NT5 5.5.5.6, NT5
// Max/Ultra 3553G 0.0.5.0 / 0.0.5.5, ST3 Pro 5.5.2.5, NT3 Pro 5.5.5.7, GT3 Pro 5.5.1.7, GT3 5.5.1.1,
// GT3 Max 6.6.1.1, ST3 7.7.1.1. Those unlock the top gear on gear 5 / lock on gear 6 (a non-gear value,
// so gear changes never re-lock); every other model keeps its stock flash-free lever untouched. Versions
// are dotted here (ver() joins the 4 chars with '.'), unlike the app's "5556" form.
const PATCHED_LATCH_FW = ['5.5.5.6', '0.0.5.0', '0.0.5.5', '5.5.2.5', '5.5.5.7', '5.5.1.7', '5.5.1.1', '6.6.1.1', '7.7.1.1', '5.5.1.5', '5.5.1.3', '8.8.1.1', '1.1.1.5', '1.1.1.6', '1.1.1.7', '2.2.2.5', '2.2.2.4', '3.3.3.5', '6.6.6.5', '7.7.7.5', '9.9.9.1', '4.4.4.9', '9.9.1.1', '8.8.8.4', '0.0.9.0', '0.0.9.9', '1.1.1.8', '7.7.7.6', '5.5.6.6', '5.0.5.0', '5.0.5.5'];
function isCapZ(){ return PATCHED_LATCH_FW.includes(detectedBldcFw); }
// Old NT5 markers: unlock on Turbo nibble 5, so the boost button alone opens full speed. Warn, refuse.
const OUTDATED_LATCH_FW = ['5.5.5.6', '0.0.5.0', '0.0.5.5'];
function isCapZOutdated(){ return OUTDATED_LATCH_FW.includes(detectedBldcFw); }

// ---------- helpers ----------
const $ = id => document.getElementById(id);
function log(m){ const el=$('log'); el.textContent += m + '\n'; el.scrollTop = el.scrollHeight; }
function hex(b){ return [...b].map(x=>x.toString(16).padStart(2,'0')).join(''); }
function hexs(b){ return [...b].map(x=>x.toString(16).padStart(2,'0')).join(' '); }
// TX log with the account id masked: a 55 AA 00 30 09 .. auth-init frame carries s(userId)
// (personal data) in bytes 7..12. Shown as XX so a copied/uploaded log never leaks it.
function hexsTx(b){
  if(b && b.length>=17 && b[0]===0x55 && b[1]===0xAA && b[3]===0x30 && b[4]===0x09){
    return [...b].map((x,i)=> (i>=7&&i<=12)?'XX':x.toString(16).padStart(2,'0')).join(' ');
  }
  return hexs(b);
}
// data-state stays the canonical english key (CSS keys off it); the visible text is translated.
function setStatus(s){ const el=$('status'); if(!el) return; el.dataset.state=s; const k='st'+s.charAt(0).toUpperCase()+s.slice(1); el.textContent = (typeof t==='function' ? t(k) : '') || s; }
const sleep = ms => new Promise(r=>setTimeout(r,ms));

function ckSum(arr){ let s=0; for(const b of arr) s=(s+b)&0xff; return s; }
// READ frame: 55 AA 00 <cmd> <ck> FE FD (BleHandler.j)
function readFrame(cmd){ const body=[0x55,0xAA,0x00,cmd]; return new Uint8Array([...body, ckSum(body),0xFE,0xFD]); }
// WRITE frame: 55 AA 00 <cmd> <len> <payload...> <ck> FE FD (BleHandler.k single byte / l byte[])
function writeFrame(cmd,payload){ payload=payload||[]; const body=[0x55,0xAA,0x00,cmd,payload.length,...payload]; return new Uint8Array([...body, ckSum(body),0xFE,0xFD]); }

// ByteUtil.s(userId, 0x88): 6 bytes big-endian of the low 48 bits of userId. The top byte (bits
// 40-47) is kept only if it is 0x01-0x7F; otherwise (0x00, or a value with the high bit set) it is
// replaced with 0x88 = TsExtractor.TS_STREAM_TYPE_DTS_HD (136). For a normal 32-bit account userId
// the top byte is 0, so this yields 88 00 b3 b2 b1 b0. (The lead byte is 0x88, NOT 0x8A.)
function s6(userId){
  let v = BigInt(Math.trunc(Number(userId))) & 0xffffffffffffn;
  const b = new Uint8Array(6);
  for(let i=5;i>=0;i--){ b[i]=Number(v & 0xffn); v>>=8n; }
  if(b[0]===0 || b[0]>=0x80) b[0]=0x88;
  return b;
}
// 0x30 auth-init: payload = [keyIdx, shareFlag, ...s6, 0x00]  (len = 9). shareFlag 0 for a random uid.
function authInitFrame(userId,keyIdx,shareFlag){ return writeFrame(CMD.AUTH_INIT, [keyIdx, shareFlag?1:0, ...s6(userId), 0x00]); }

// AES-128-ECB of one 16-byte block (WebCrypto CBC with zero IV == ECB for the first block)
async function aesEcb16(key16, block16){
  const k = await crypto.subtle.importKey('raw', key16, {name:'AES-CBC'}, false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({name:'AES-CBC', iv:new Uint8Array(16)}, k, block16));
  return ct.slice(0,16);
}
function xor16(block16, key16){ const o=new Uint8Array(16); for(let i=0;i<16;i++) o[i]=(block16[i]^key16[i])&0xff; return o; }
// Response mode matches the OEM: for a challenge with a leading mode byte, mode 0 = XOR, else AES.
async function authRespFrame(block16,keyIdx,useXor){ const ct = useXor ? xor16(block16, KEYS[keyIdx]) : await aesEcb16(KEYS[keyIdx], block16); return writeFrame(CMD.AUTH_RESP, [...ct]); }

function parseHexFrame(s){
  const clean=(s||'').replace(/[^0-9a-fA-F]/g,''); if(clean.length<8||clean.length%2) return null;
  return new Uint8Array(clean.match(/../g).map(h=>parseInt(h,16)));
}

// ---------- Bluetooth log -> auth frame (fully local, nothing uploaded) ----------
// The user enables the Android "Bluetooth HCI snoop log", connects once with the real NAVEE app,
// then drops the resulting file here. We pull the app's 0x30 auth frame (55 AA 00 30 .. FE FD) out of
// the raw bytes, so the user never has to touch Wireshark or copy any hex. Accepts a raw btsnoop .log,
// a .gz, or an Android bug-report .zip (unzipped in-browser via the native DecompressionStream).
function scanAuthFrame(bytes){
  // Return the LAST fully valid 55 AA 00 30 <len> <payload> <cksum> FE FD frame (most recent connect).
  let found=null;
  for(let i=0;i+8<bytes.length;i++){
    if(bytes[i]!==0x55||bytes[i+1]!==0xAA||bytes[i+2]!==0x00||bytes[i+3]!==0x30) continue;
    const len=bytes[i+4], total=len+8;
    if(i+total>bytes.length) continue;
    if(bytes[i+6+len]!==0xFE||bytes[i+7+len]!==0xFD) continue;
    let s=0; for(let k=i;k<=i+4+len;k++) s=(s+bytes[k])&0xff;   // checksum = sum(0x55..last payload byte)
    if(s!==bytes[i+5+len]) continue;
    found=bytes.slice(i,i+total);
  }
  return found;
}
async function tryDecompress(bytes, fmt){
  try{
    if(typeof DecompressionStream!=='function') return null;
    const ds=new DecompressionStream(fmt);
    const st=new Blob([bytes]).stream().pipeThrough(ds);
    return new Uint8Array(await new Response(st).arrayBuffer());
  }catch(e){ return null; }
}
function zipEntries(b){
  const out=[], dv=new DataView(b.buffer,b.byteOffset,b.byteLength);
  let eocd=-1;
  for(let i=b.length-22;i>=0 && i>b.length-22-0x10000;i--){ if(b[i]===0x50&&b[i+1]===0x4b&&b[i+2]===0x05&&b[i+3]===0x06){ eocd=i; break; } }
  if(eocd<0) return out;
  let n=dv.getUint16(eocd+10,true), p=dv.getUint32(eocd+16,true);
  for(let e=0;e<n && p+46<=b.length;e++){
    if(dv.getUint32(p,true)!==0x02014b50) break;
    const method=dv.getUint16(p+10,true), compSize=dv.getUint32(p+20,true);
    const nameLen=dv.getUint16(p+28,true), extraLen=dv.getUint16(p+30,true), commentLen=dv.getUint16(p+32,true), lho=dv.getUint32(p+42,true);
    let name=''; for(let k=0;k<nameLen;k++) name+=String.fromCharCode(b[p+46+k]);
    out.push({name,method,compSize,lho});
    p+=46+nameLen+extraLen+commentLen;
  }
  return out;
}
function zipEntryData(b, ent){
  const dv=new DataView(b.buffer,b.byteOffset,b.byteLength);
  if(dv.getUint32(ent.lho,true)!==0x04034b50) return null;
  const start=ent.lho+30+dv.getUint16(ent.lho+26,true)+dv.getUint16(ent.lho+28,true);
  return b.slice(start, start+ent.compSize);
}
async function extractAuthFromLog(file){
  const raw=new Uint8Array(await file.arrayBuffer());
  let f=scanAuthFrame(raw); if(f) return f;                                   // raw btsnoop .log or stored bytes
  if(raw[0]===0x1f&&raw[1]===0x8b){ const g=await tryDecompress(raw,'gzip'); if(g){ f=scanAuthFrame(g); if(f) return f; } }
  if(raw[0]===0x50&&raw[1]===0x4b){                                           // a ZIP (Android bug report)
    const ents=zipEntries(raw);
    ents.sort((a,b2)=>(/(btsnoop|bluetooth|bt)/i.test(b2.name)?1:0)-(/(btsnoop|bluetooth|bt)/i.test(a.name)?1:0));
    for(const ent of ents){
      const data=zipEntryData(raw,ent); if(!data) continue;
      let dec = ent.method===0 ? data : await tryDecompress(data,'deflate-raw');
      if(!dec) continue;
      f=scanAuthFrame(dec); if(f) return f;
      if(dec[0]===0x1f&&dec[1]===0x8b){ const g=await tryDecompress(dec,'gzip'); if(g){ f=scanAuthFrame(g); if(f) return f; } }
    }
  }
  return null;
}
async function handleLogFile(file){
  if(!file) return;
  log((t('logParsing')||'reading log')+': '+file.name);
  try{
    const f=await extractAuthFromLog(file);
    if(!f){ log(t('logNoFrame')||'no auth frame found in the log. Enable the Bluetooth HCI snoop log, then connect once with the real NAVEE app, then upload the log/bug-report.'); return; }
    const hexStr=hex(f);
    const ah=$('authhex-in'); if(ah){ ah.value=hexStr; const det=ah.closest&&ah.closest('details'); if(det) det.open=true; }
    const u=$('uid-in'); if(u){ u.value=''; try{ localStorage.setItem('navee.uid',''); }catch(e){} }
    try{ localStorage.setItem('navee.authhex', hexStr); }catch(e){}
    log(t('logFrameFromLog')||'auth frame found in the log and stored -> Connect is ready.');
    if(!connected) refreshButtons();
  }catch(e){ log('log parse failed: '+(e&&e.message||e)); }
}

// ---------- BLE ----------
let device=null, writeCh=null, notifyCh=null, connected=false, authed=false, curKeyIdx=0, autoReadDone=false, lastMaxSpeed=null, usingRandomUid=false, phase2Sent=false, afterAuthDone=false, lastSerialData=null, lastLockState=null, lastFault=null, faultPollTimer=null;
// After the challenge/response succeeds the app runs a fixed routine: time sync (0x6F sub 6) then the
// status reads. We mirror it once per connection.
async function afterAuth(){
  if(afterAuthDone) return; afterAuthDone=true;
  await afterConnectCommon();
}
// Runs once per connection, after auth (if a userId was given) OR directly after connect when none was
// given - the normal commands and the status reads need no auth (meter dispatcher has no auth gate).
async function afterConnectCommon(){
  await writeTimeSync();
  // OEM tail of the handshake: after the clock it sends 0x7B, which arms the scooter's 0x90 stream
  // and keeps the link open. Only on the authed path (a bound scooter needs it).
  if(authed){ try{ await sendFrame(readFrame(0x7B)); log('sent 0x7B (session arm)'); }catch(e){} }
  autoRead();
  maybeRunDeepAction();
}
// 0x6F sub-command 6 = clock sync. Payload = 06 + local epoch seconds (UTC + timezone offset), 4 bytes
// big-endian, exactly like BleHandler time sync (ByteUtil.u(...,true)).
async function writeTimeSync(){
  try{
    const local = Math.floor(Date.now()/1000) - (new Date().getTimezoneOffset()*60);
    const t=[(local>>>24)&0xff,(local>>>16)&0xff,(local>>>8)&0xff,local&0xff];
    await sendFrame(writeFrame(0x6F,[0x06,...t]));
    log('time sync sent (0x6F sub 6)');
  }catch(e){ log('time sync failed: '+(e&&e.message||e)); }
}
// Read status once, automatically, right after authentication so the live values and the
// model-specific settings appear without the user pressing Read.
function autoRead(){ if(autoReadDone) return; autoReadDone=true; setTimeout(()=>{ if(writeCh) readStatus(); }, 500); }
let waiters=[];   // resolve on next report of a given cmd
function waitReport(cmd, ms=3000){
  return new Promise(res=>{ const w={cmd,res}; waiters.push(w); setTimeout(()=>{ waiters=waiters.filter(x=>x!==w); res(null); }, ms); });
}

async function sendFrame(bytes){
  if(!writeCh) throw new Error('not connected');
  log('TX '+hexsTx(bytes));
  // Match the app: FastBle never forces a write type (BleConnector.q sets no write type), and b002
  // advertises write-without-response (the DFU path explicitly sets NO_RESPONSE on b002), so the app
  // writes control frames as a write COMMAND (no response). The real reply always comes back over the
  // b003 notify, not the GATT write ack. So prefer write-without-response, with-response as fallback.
  if(writeCh.writeValueWithoutResponse){ try{ await writeCh.writeValueWithoutResponse(bytes); return; }catch(e){} }
  if(writeCh.writeValueWithResponse){ await writeCh.writeValueWithResponse(bytes); }
  else await writeCh.writeValue(bytes);
}

let rx=[];
function onNotify(ev){
  for(const b of new Uint8Array(ev.target.value.buffer)) rx.push(b);
  for(;;){
    const start=rx.findIndex((b,i)=>b===0x55&&rx[i+1]===0xAA);
    if(start<0){ rx=[]; break; }
    if(start>0) rx=rx.slice(start);
    // normal frames end FE FD; the undocumented factory frames (cmd >= 0xA0) end AE AD
    const end=rx.findIndex((b,i)=>(b===0xFE&&rx[i+1]===0xFD)||(b===0xAE&&rx[i+1]===0xAD&&rx[3]>=0xA0));
    if(end<0) break;
    handleFrame(new Uint8Array(rx.slice(0,end+2))); rx=rx.slice(end+2);
  }
}

// RX layout (verified): [0]55 [1]AA [2]flag [3]cmd [4]len [5]errcode [6..]data <ck> FE FD
// len counts errcode + data, so data = frame[6 .. 5+len].
function frameParts(f){
  const cmd=f[3], len=f[4], err=f[5];
  const data=f.slice(6, 5+len);
  return {cmd, len, err, data};
}

async function handleFrame(f){
  log('RX '+hexs(f));
  const {cmd, err, data} = frameParts(f);
  if(cmd===CMD.AUTH_INIT){                 // 0x30 from scooter
    if(err!==0){                           // scooter rejected the init (no challenge follows)
      setStatus('error');
      if(err===255){ log(t('logAuth255') || 'auth rejected (255): the scooter is bound to an account; enter its numeric account userId (not the Navee-ID) under Advanced.'); }
      else log('auth error code '+err);
      return;
    }
    if(data.length>=16){                   // challenge present
      // OEM: challenge longer than 16 carries a leading mode byte (0 = XOR, else AES) then 16 bytes;
      // a bare 16-byte challenge has no mode byte and uses AES.
      let block, useXor;
      if(data.length>16){ useXor=(data[0]===0); block=data.slice(1,17); }
      else { useXor=false; block=data.slice(0,16); }
      log('auth challenge received, responding (key '+curKeyIdx+', '+(useXor?'xor':'aes')+')');
      await sendFrame(await authRespFrame(block, curKeyIdx, useXor));
    } else {                               // short ack (no challenge) = fully authenticated
      if(!authed){ authed=true; setStatus('connected'); refreshButtons(); log('authenticated'); }
      await afterAuth();                    // time sync + status reads, like the app
    }
    return;
  }
  if(cmd===CMD.AUTH_RESP){                  // 0x31 result (challenge accepted)
    if(err===0){
      // Phase 2, exactly like the app: after a good 0x31 it sends 0x30 once more; the scooter then
      // answers with a short 0x30 (no challenge) which we treat as fully authenticated above.
      if(!phase2Sent){ phase2Sent=true; log('auth response accepted, phase-2 init'); await sendPhase2Init(); }
      else { if(!authed){ authed=true; setStatus('connected'); refreshButtons(); log('authenticated'); } await afterAuth(); }
    }
    else log('auth response rejected, code '+err);
    return;
  }
  // fulfil any waiter for this cmd
  const w=waiters.find(x=>x.cmd===cmd); if(w){ waiters=waiters.filter(x=>x!==w); w.res(f); }
  if(cmd===CMD.REPORT) decodeParams(f);
  if(cmd===CMD.SN_REPORT) decodeSN(f);
  if(cmd===CMD.READ_BATTERY) decodeBattery(f);
  if(cmd===CMD.READ_FW) decodeFirmware(f);
  if(cmd===0x90||cmd===0x91||cmd===0x92) decodeRealtime(cmd,f);
  if(cmd===0xA2) log('factory config-write ack (0xA2) received');
  if(cmd===0xA0) log('factory line-test ack (0xA0)');
  if(cmd===0xBE) decodeLock(f);
  if(cmd===0xB9) decodeFactoryConfig(f);
}

// read len bytes from p at off; z2=true big-endian, z2=false little-endian (matches ByteUtil.p)
function rd(p,off,len,z2){ if(off+len>p.length) return null; if(len===1) return p[off]&0xff; let b=[...p.slice(off,off+len)]; if(!z2) b=b.reverse(); let v=0; for(const x of b) v=v*256+(x&0xff); return v; }
// set a telemetry tile: fill value and reveal its wrapper (report-gated)
function setTile(key,val){ const b=$('tv-'+key), w=$('tile-'+key); if(b) b.textContent=val; if(w) w.hidden=false; }
function resetTiles(){ document.querySelectorAll('#tele-card .tile').forEach(el=>el.hidden=true); const e=$('tele-empty'); if(e) e.hidden=false; }
function teleSeen(){ const e=$('tele-empty'); if(e) e.hidden=true; }

// Full vehicle param report (cmd 0x70). Offsets are into the DATA block (byte[6]+), taken
// verbatim from DeviceCarInfo parsing in BleHandler.G case 112 (v2.1.6). Raw is logged too.
function decodeParams(f){
  const {err, data:p} = frameParts(f);
  if(err!==0){ log('param report error code '+err); return {}; }
  const at=i=> (i<p.length? p[i] : null);
  const o = {
    lock:        at(2),
    unit:        at(7),   // mileage unit (0 km / 1 mph)
    startSpeed:  at(19),
    limitSpeed:  at(20),
    maxSpeed:    at(25),
    driveMode:   at(26),
    breakSpeed:  at(35),
  };
  // the custom-limit byte carries the enable flag in bit7; show the plain value too
  const limitVal = o.limitSpeed==null ? null : (o.limitSpeed & 0x7f);
  if(o.maxSpeed!=null){ $('t-max').textContent = o.maxSpeed; lastMaxSpeed=o.maxSpeed; }
  if(limitVal!=null)    $('t-limit').textContent = limitVal + (o.limitSpeed & 0x80 ? ' (on)' : ' (off)');
  log(`params: max=${o.maxSpeed} limit=${limitVal} start=${o.startSpeed} mode=${o.driveMode} lock=${o.lock} unit=${o.unit}`);
  log('raw param data: '+hexs(p));
  applyReportToSettings(p);
  return o;
}
function decodeSN(f){
  const {err, data:p} = frameParts(f);
  if(err!==0){ log('SN report error code '+err); return; }
  lastSerialData = Array.from(p);           // raw config block, for region read-modify-write
  let sn=''; for(const c of p){ if(c>=0x20&&c<0x7f) sn+=String.fromCharCode(c); }
  sn=sn.trim();
  if(sn.length>=10){ const area=sn.substring(8,10); detectedSku=skuOf(area); $('t-sn').textContent=sn; $('t-region').textContent=area; $('t-sku').textContent=detectedSku; log('serial '+sn+' -> region '+area+' (SKU '+detectedSku+')'); updateRegionToggle(); detectModel(sn); }
  else log('SN report: '+hexs(f));
}
// Resolve the connected model from the serial and update the feature card + gating.
function detectModel(sn){
  const pid=pidOf(sn);
  detectedCaps = pid ? (MODELS[pid]||null) : null;
  detectedSpeed = pid ? (SPEED[pid]||null) : null;
  detectedModel = detectedCaps ? detectedCaps[0] : null;
  const el=$('t-model'); if(el) el.textContent = detectedModel || (pid ? ('? ('+pid+')') : '-');
  if(detectedModel) log('model: '+detectedModel+' (pid '+pid+')'+(detectedSpeed?' - speed lever available':''));
  else if(pid) log('model: unknown pid '+pid+' - features shown unverified');
  applyModelCaps();
}
// Show the three drive-functions per the detected model. lock is universal; cruise/kick follow the
// firmware sweep: 1 -> supported (show), 0 -> not supported (hide), null/unknown -> show as unverified.
function applyModelCaps(){
  const set=(key,cap)=>{ const row=$('row-'+key); if(!row) return;
    if(!connected){ row.hidden=true; row.classList.remove('caution'); return; }
    if(cap===0){ row.hidden=true; row.classList.remove('caution'); }
    else { row.hidden=false; row.classList.toggle('caution', cap==null); } };
  set('lock', 1);                                   // Wegfahrsperre - whole line supports 0x51
  set('cruise', detectedCaps ? detectedCaps[1] : null);
  set('zero',   detectedCaps ? detectedCaps[2] : null);
  // Zero-start levels 0-2 (ride off without pushing) are USA-SKU only; the meter clamps them to 3
  // elsewhere. Hide them on non-USA units; the row still offers 3-5 (push-off threshold). Verified:
  // meter clamp FUN_08014230, start-speed USA gate in navee_gesamtanalyse.md.
  const zsel=$('zero-in'); if(zsel) zsel.querySelectorAll('option').forEach(o=>{ if(parseInt(o.value,10)<3) o.hidden=(detectedSku!=='USA'); });
  const fm=$('fn-model');
  if(fm) fm.textContent = connected
    ? (detectedModel ? t('fnModel').replace('%s', detectedModel) : t('fnModelUnknown'))
    : t('fnConnect');
  // Speed card (gear lever): the four flash-free families (detectedSpeed), plus any scooter running
  // our capZ latch firmware (isCapZ, controller marker 5.5.5.6).
  const tc=$('tu-card'); const showSpeed = connected && (!!detectedSpeed || isCapZ());
  if(tc) tc.hidden = !showSpeed;
  const sh=$('tu-model-hint'); if(sh){ sh.textContent = isCapZ() ? (isCapZOutdated() ? t('capzOutdated') : t('capzHint')) : (detectedSpeed ? detectedSpeed[lang==='en'?1:0] : ''); sh.classList.toggle('hint-warn', isCapZ() && isCapZOutdated()); sh.hidden = !showSpeed; }
  // The flash-free notes (tuHint/tuBehavior) do not apply to capZ firmware, hide them there.
  const th=$('tu-hint'); if(th) th.hidden = isCapZ();
  const tb=$('tu-behavior'); if(tb) tb.hidden = isCapZ();
  updateRegionToggle();   // refresh the unlock/lock buttons once the firmware marker is known
}
// Factory reply payload: 55 AA 00 <cmd> <len> <payload...> <cksum> AE AD (payload = len bytes at [5]).
function factoryPayload(f){ const len=f[4]||0; return f.slice(5, 5+len); }
// 0xBE reply: config-write lock state (bldc DAT_20000756). Per the controller code 0 = writable, non-0 = locked.
function decodeLock(f){
  const p=factoryPayload(f);
  if(!p.length){ log('lock (BE): no payload in '+hexs(f)); return; }
  const state=p[p.length-1];   // payload is [status, state]; state is the last byte
  lastLockState=state;
  log('config-write lock (BE): 0x'+state.toString(16)+' -> '+(state===0
    ? 'WRITABLE (unlocked)'
    : 'LOCKED (controller drops config writes; no BLE clear exists -> region change needs hardware/SWD)'));
}
// 0xB9 reply: live controller config (first 17 bytes = config block; region letters at 8-9).
function decodeFactoryConfig(f){
  const p=factoryPayload(f);
  let s=''; for(const c of p){ if(c>=0x20&&c<0x7f) s+=String.fromCharCode(c); } s=s.trim();
  const region=(s.length>=10)?s.substring(8,10):'??';   // region letters are chars 8-9 of the serial string
  log('live config (B9): "'+s+'" region='+region+' | back up this line before any write');
  const sn=(($('t-sn')&&$('t-sn').textContent)||'').trim();
  if(sn && sn!=='-'){
    const match = !!s && (s.indexOf(sn)>=0 || sn.indexOf(s)>=0);
    log('B9 vs 0x74 serial "'+sn+'": '+(match
      ? 'MATCH -> 0x74 mirrors the config block; region IS BLE-writable via A2 when unlocked'
      : 'MISMATCH -> 0x74 reads the serial block; region NOT BLE-writable (wired/SWD only)'));
  }
}
// Battery report (cmd 0x72). Offsets from DeviceBatteryInfo (BleHandler.G case 114).
function decodeBattery(f){
  const {err, data:p} = frameParts(f); if(err!==0){ log('battery error code '+err); return; }
  teleSeen();
  const charge=rd(p,1,1), volt=rd(p,2,4,false), curr=rd(p,6,4,false), health=rd(p,10,1), temp=rd(p,11,1), cyc=rd(p,13,2,false);
  if(charge!=null) setTile('batt', charge+' %');
  // App (DeviceBatteryInfoActivity.f0) shows this value verbatim as " mV" -> report is millivolt.
  if(volt!=null)   setTile('volt', (volt/1000).toFixed(2)+' V');
  // App (g0): bit 31 is a sign flag. Set -> discharge (negative); the low 31 bits are the mA magnitude.
  if(curr!=null){ const mA = (curr & 0x80000000) ? -(curr & 0x7fffffff) : curr; setTile('curr', (mA/1000).toFixed(2)+' A'); }
  if(health!=null) setTile('health', health+' %');
  if(temp!=null)   setTile('temp', temp+' C');
  if(cyc!=null)    setTile('cycles', cyc);
  log('battery: charge='+charge+' volt(raw)='+volt+' health='+health+' temp='+temp+' cycles='+cyc);
  log('raw battery data: '+hexs(p));
}
// Firmware report (cmd 0x73). Five 4-byte ASCII version blocks (BleHandler.G case 115 -> q()).
function decodeFirmware(f){
  const {err, data:p} = frameParts(f); if(err!==0){ log('firmware error code '+err); return; }
  teleSeen();
  const ver=(o)=>{ if(o+4>p.length) return null; let s=[]; for(let i=o;i<o+4;i++) s.push(String.fromCharCode(p[i])); return s.join('.'); };
  const parts={ meter:ver(0), bldc:ver(4), bms:ver(8), screen:ver(12), uwb:ver(16) };
  for(const k in parts){ if(parts[k]!=null) setTile('fw-'+k, parts[k]); }
  detectedBldcFw = parts.bldc;   // capZ marker 5.5.5.6 gates the capZ lock/unlock card
  applyModelCaps();
  log('firmware: '+JSON.stringify(parts));
}
// Live reports (0x90 home, 0x91/0x92 sub). Speed, mode, mileage, fault code.
function decodeRealtime(cmd,f){
  const {err, data:p} = frameParts(f); if(err!==0) return;
  teleSeen();
  if(cmd===0x90){
    const fault=rd(p,0,1), mode=rd(p,1,1), charge=rd(p,2,1), range=rd(p,6,1);
    if(fault!=null){
      setTile('fault', fault===0 ? '0 (ok)' : String(fault));
      // Log every change of the warn/fault byte: this is the value the meter's beep gate reads;
      // anything not in {0,E,T,U,V,W} makes the continuous beep. Correlate with speed/mode above.
      if(fault!==lastFault){ lastFault=fault; log('warn/fault code: '+fault+' (0x'+fault.toString(16)+')'+(fault!==0?' - continuous beep unless in {0,E,T,U,V,W}':'')); }
    }
    if(mode!=null)  setTile('mode', mode);
    if(charge!=null) setTile('batt', charge+' %');
    if(range!=null) setTile('range', range+' km');
  } else if(cmd===0x91){
    const spd=rd(p,2,1), range=rd(p,3,1), total=rd(p,8,1);
    if(spd!=null) setTile('speed', spd+' km/h');
    if(range!=null) setTile('range', range+' km');
    if(total!=null) setTile('total', total+' km');
  } else if(cmd===0x92){
    const spd=rd(p,2,2,false), total=rd(p,12,2,false);
    if(spd!=null) setTile('speed', (spd/10).toFixed(1)+' km/h');
    if(total!=null) setTile('total', total+' km');
  }
}

async function connect(){
  try{
    setStatus('connecting');
    // The app scans and matches by NAME (name.contains("NAVEE")); the scooter does not advertise
    // the 128-bit service UUID, so filtering by service would show an empty chooser. Filter by name
    // and declare the service as optional so we can use it after connecting.
    const showAll = $('showall') && $('showall').checked;
    const opts = showAll
      ? { acceptAllDevices:true, optionalServices:[SERVICE] }
      : { filters:[{namePrefix:'NAVEE'}], optionalServices:[SERVICE] };
    const dev=await navigator.bluetooth.requestDevice(opts);
    await connectDevice(dev);
  }catch(e){ setStatus('error'); const m=(e&&e.message)||String(e); log('connect failed: '+m);
    if(/GATT|unknown reason|connection/i.test(m)){ const h=t('logGattHint'); if(h) log(h); } }
}
// Connect to an already-chosen BluetoothDevice (used by connect() and by the shortcut auto-reconnect).
async function connectDevice(dev){
  setStatus('connecting');
  device=dev;
  try{ if(device.id) localStorage.setItem('navee.device', device.id); }catch(e){}
  try{ device.removeEventListener('gattserverdisconnected', onDisconnect); }catch(e){}   // avoid stacking on repeated connect attempts
  device.addEventListener('gattserverdisconnected', onDisconnect);
  // Android Web Bluetooth GATT ops fail transiently ("GATT operation failed for unknown reason"),
  // most often when the scooter is still held by the official app or the OS. Retry the GATT setup a
  // few times with a fresh connection before giving up.
  let lastErr=null, ok=false;
  for(let attempt=1; attempt<=4 && !ok; attempt++){
    try{
      const server=await device.gatt.connect();
      // Query the service tolerating the Android discovery race ("No Services matching UUID") with a
      // couple of short retries, but bail immediately to a fresh connect if the link already dropped
      // ("GATT Server is disconnected") - some scooters drop the connection when the app still holds it.
      let svc=null, se=null;
      for(let k=0;k<3;k++){
        try{ svc=await server.getPrimaryService(SERVICE); break; }
        catch(e){ se=e; if(!server.connected) throw e; await sleep(250); }
      }
      if(!svc) throw (se || new Error('service discovery failed'));
      writeCh=await svc.getCharacteristic(WRITE_CHAR);
      notifyCh=await svc.getCharacteristic(NOTIFY_CHAR);
      await notifyCh.startNotifications();
      notifyCh.addEventListener('characteristicvaluechanged', onNotify);
      ok=true;
    }catch(e){
      lastErr=e;
      if(attempt<4) log('BLE setup attempt '+attempt+' failed ('+(e&&e.message||e)+') - retrying...');
      try{ if(device.gatt&&device.gatt.connected) device.gatt.disconnect(); }catch(_){}
      await sleep(800);
    }
  }
  if(!ok) throw (lastErr || new Error('GATT setup failed'));
  connected=true; authed=false; autoReadDone=false; setStatus('connected');
  log('connected to '+(device.name||device.id)); refreshButtons();
  await sleep(150);
  // The userId auth (0x30) is OPTIONAL: the meter dispatches every normal command with no auth gate
  // (verified in the firmware). Run auth only if a userId / auth frame was supplied; otherwise read
  // the status directly and enable the features.
  if(hasAuthCreds()){ await authenticate(); }
  else { log('no userId supplied - the normal features and status reads need no auth; continuing directly'); afterAuthDone=true; await afterConnectCommon(); }
}

// Build the 0x30 AUTH_INIT frame from the pasted hex frame or from the userId field. Returns null only
// when a hex frame was pasted but is unparseable. A fresh random keyIdx is drawn each call (as the app
// does via SecureRandom H(0,4)), so phase 1 and phase 2 use independent keys.
function buildInitFrame(){
  const hexIn=(($('authhex-in')&&$('authhex-in').value)||'').trim();
  if(hexIn){ const f=parseHexFrame(hexIn); if(!f) return null; curKeyIdx=f[5]??0; usingRandomUid=false; return f; }
  const raw=(($('uid-in')&&$('uid-in').value)||'').trim();
  const ov=parseInt(raw,10);
  let uid;
  if(raw!=='' && Number.isFinite(ov) && ov>0){
    uid=ov; usingRandomUid=false;
    if(uid>2147483647) log(t('logUidRange') || ('note: the account userId is a 32-bit number (max 2147483647); '+raw+' is too large to be a valid userId'));
  } else { uid=AUTO_UID; usingRandomUid=true; }   // no id given -> random (only works on an unbound scooter)
  curKeyIdx=secRandInt(KEYS.length);
  return authInitFrame(uid,curKeyIdx,!usingRandomUid);
}
async function authenticate(){
  phase2Sent=false; afterAuthDone=false;
  const f=buildInitFrame();
  if(!f){ log('invalid auth hex'); return; }
  log('auth init (key '+curKeyIdx+', uid '+(usingRandomUid?'random':'set')+')');   // never log the account id in the clear
  await sendFrame(f);   // the 0x30 challenge reply is handled in handleFrame
}
// Phase 2: after a good 0x31 the app sends 0x30 once more (fresh keyIdx). Reuses the same userId/hex.
async function sendPhase2Init(){
  const f=buildInitFrame();
  if(!f) return;
  log('auth phase-2 init (key '+curKeyIdx+')');
  await sendFrame(f);
}

async function readStatus(){
  if(!writeCh){ log('not connected'); return; }
  await sendFrame(readFrame(CMD.READ_SN));     // 0x74 -> serial/region (source of the SKU)
  await sleep(300);
  await sendFrame(readFrame(CMD.READ_PARAMS)); // 0x70 -> full param block incl. speeds
  await sleep(300);
  await sendFrame(readFrame(CMD.READ_BATTERY));// 0x72 -> battery telemetry
  await sleep(300);
  await sendFrame(readFrame(CMD.READ_FW));     // 0x73 -> firmware versions
  startFaultPoll();
}

// Poll the homepage report (0x90) once a second so the warn/fault code shows live even when the
// scooter is not pushing it (it only pushes while riding). decodeRealtime logs the code on change.
function startFaultPoll(){
  if(faultPollTimer) return;
  faultPollTimer = setInterval(() => { if(writeCh && connected) sendFrame(readFrame(0x90)).catch(()=>{}); }, 1000);
}
function stopFaultPoll(){ if(faultPollTimer){ clearInterval(faultPollTimer); faultPollTimer=null; } }

// ----- writers -----
// Direct custom speed limit (0x6B). enabled sets bit7 (limit active).
async function writeLimitSpeed(kmh, enabled){
  if(!writeCh){ log('not connected'); return; }
  const val=((kmh&0x7f) | (enabled?0x80:0)) & 0xff;
  await sendFrame(writeFrame(CMD.LIMIT_SPEED, [val]));
  log('limit speed -> '+(kmh&0x7f)+' km/h '+(enabled?'(on)':'(off)'));
}
// Direct max speed (0x6E, subcmd 01).
async function writeMaxSpeed(kmh){
  if(!writeCh){ log('not connected'); return; }
  await sendFrame(writeFrame(CMD.MAX_SPEED, [0x01, kmh&0xff]));
  log('max speed -> '+(kmh&0xff)+' km/h');
}
function drOpenVal(){ return parseInt(($('open-in')||{}).value||'50',10)||50; }
function drLockedVal(){ return parseInt(($('locked-in')||{}).value||'20',10)||20; }
function persistDrossel(){ try{ localStorage.setItem('navee.open', String(drOpenVal())); localStorage.setItem('navee.locked', String(drLockedVal())); }catch(e){} }
function loadDrossel(){ try{ const o=localStorage.getItem('navee.open'), l=localStorage.getItem('navee.locked'); if(o&&$('open-in')) $('open-in').value=o; if(l&&$('locked-in')) $('locked-in').value=l; }catch(e){} }
// Direct startup speed (0x6A). value 0 = zero-start, higher = push-to-start threshold.
async function writeStartSpeed(v){
  if(!writeCh){ log('not connected'); return; }
  await sendFrame(writeFrame(CMD.START_SPEED, [v&0xff]));
  log('start speed -> '+(v&0xff));
}
// Single-byte setting write, e.g. a 0/1 toggle: 55 AA 00 <cmd> 01 <v> ... (BleHandler.k)
async function writeToggle(cmd, v){
  if(!writeCh){ log('not connected'); return; }
  await sendFrame(writeFrame(cmd, [v&0xff]));
  log('set 0x'+cmd.toString(16)+' -> '+(v&0xff));
}
// Param sub-command write: 55 AA 00 <cmd> 02 <sub> <v> ... (BleHandler.l), e.g. 0x6F long-range.
async function writeSub(cmd, sub, v){
  if(!writeCh){ log('not connected'); return; }
  await sendFrame(writeFrame(cmd, [sub&0xff, v&0xff]));
  log('set 0x'+cmd.toString(16)+' sub '+sub+' -> '+(v&0xff));
}
// Sound (0x6C): volume byte with bit7 = sound on, second byte = language (0). {vol|0x80, 0}
async function writeSound(v){
  if(!writeCh){ log('not connected'); return; }
  await sendFrame(writeFrame(0x6C, [((v&0x7f)|0x80)&0xff, 0]));
  log('sound volume -> '+(v&0x7f));
}

function factoryFrame(sub, payload){
  payload = payload || [];
  const body = [0x55,0xAA,0x00,sub,payload.length,...payload];
  return new Uint8Array([...body, ckSum(body), 0xAE, 0xAD]);
}
function curRegion(){
  if(lastSerialData && lastSerialData.length>=10)
    return String.fromCharCode(lastSerialData[8]||0)+String.fromCharCode(lastSerialData[9]||0);
  const el=$('t-region'); return (el && el.textContent && el.textContent!=='-') ? el.textContent : null;
}
function regUnlockCode(){ return ((($('region-open-in')||{}).value||'US').toUpperCase().replace(/[^A-Z]/g,'').slice(0,2))||'US'; }
function regLockCode(){ return ((($('region-lock-in')||{}).value||'DE').toUpperCase().replace(/[^A-Z]/g,'').slice(0,2))||'DE'; }
function regIsUnlocked(){ const r=curRegion(); return r!=null && r===regUnlockCode(); }
// Speed unlock is the flash-free "gear 4" trick: BLE 0x58 writes the gear/drive-mode byte; setting it
// to 4 makes the meter command the SKU top-speed value (fixed by firmware), which the controller caps
// at up to 50.8 km/h. It is per-session (a physical gear change to S or a reboot reverts it), so this
// is not persistent. speedUnlocked tracks only what THIS page last sent.
let speedUnlocked=false;
function updateRegionToggle(){
  const b=$('btn-regiontoggle'); if(!b) return;
  const lb=$('btn-speedlock');
  // Two send-only buttons, no page flag: primary always unlocks, second always locks (value per model
  // in speedGear). No stale state, so a reload never re-sends the wrong command.
  b.textContent = t('btnSpeedUnlock')||'Speed freischalten';
  if(lb){ lb.hidden=false; lb.textContent = t('btnSpeedLock')||'Drossel sperren (22 km/h)'; }
}
// Write a 2-letter region code into serial chars 8-9 via the factory 0xA2 config write.
async function writeRegionCode(code){
  if(!writeCh){ log('not connected'); return; }
  if(!/^[A-Z]{2}$/.test(code)){ log('region code must be 2 letters'); return; }
  if(!lastSerialData || lastSerialData.length<17){ log('reading serial/config first...'); await sendFrame(readFrame(CMD.READ_SN)); await sleep(700); }
  if(!lastSerialData || lastSerialData.length<17){ log('could not read serial - aborting region write'); return; }
  const cfg = Array.from(lastSerialData).slice(0,17);
  const before = String.fromCharCode(cfg[8])+String.fromCharCode(cfg[9]);
  cfg[8]=code.charCodeAt(0); cfg[9]=code.charCodeAt(1);
  log('region write '+before+' -> '+code+' (factory 0xA2 config write)');
  try{
    await sendFrame(factoryFrame(0xA0,[0x01]));   // enter line-test so the readback echoes to BLE (display goes dark)
    await sleep(500);
    await sendFrame(factoryFrame(0xA2, cfg));      // config write, full 17 bytes (controller sub 0x16)
    await sleep(500);
    await sendFrame(factoryFrame(0xB9));           // read the live config back (decodeFactoryConfig logs it)
    await sleep(1500);
    await sendFrame(readFrame(CMD.READ_SN));       // also refresh the 0x74 tile
    await sleep(400);
  } finally {
    await sendFrame(factoryFrame(0xA0,[0x00]));   // ALWAYS exit line-test -> display back on
  }
  setTimeout(()=>{ log('write sent -> check the B9 line above: region '+code+' there means it took (power-cycle and test); unchanged means the controller rejected it (lock) or 0x74 reads the serial'); updateRegionToggle(); }, 900);
}
// 0x58 gear lever. capZ-flashed scooters unlock on 5 / lock on 6 (non-gear value, survives gear
// changes). Unflashed: NT-family open on 5 / throttle on 2; all others use 4 / 3.
function speedGear(open){ if(isCapZ()) return open ? 5 : 6; const nt=/^NT/i.test(detectedModel||''); return open ? (nt?5:4) : (nt?2:3); }
// No auth-lock or config-lock gate applies to the gear byte, so this works even where a region write
// would be dropped.
async function doSpeedUnlock(){
  if(!writeCh){ log('not connected'); return; }
  if(isCapZ()){
    if(isCapZOutdated()){ log('outdated firmware ('+detectedBldcFw+') - unlock disabled, it is bypassable at the scooter boost button. Rebuild and flash the current firmware on nv-fw.'); updateRegionToggle(); return; }
    await writeToggle(0x58, 7);        // app-only unlock (nibble 7); no physical control emits it
    await sleep(600);
    await writeToggle(0x58, 3);        // back to a normal gear; ceiling stays raised
    speedUnlocked=true; updateRegionToggle();
    log('speed unlock: top-gear ceiling raised. Now press the boost button on the scooter to use it. A restart locks it back to 22.');
    return;
  }
  const g=speedGear(true);
  await writeToggle(0x58, g);
  speedUnlocked=true; updateRegionToggle();
  log('speed unlock: gear '+g+' sent -> meter commands the SKU top speed for '+(detectedModel||'this model')+'. The firmware clamps it to the unit SKU/region. Per session; a gear change to S or a reboot reverts it.');
}
async function doSpeedLock(){
  if(!writeCh){ log('not connected'); return; }
  const g=speedGear(false);
  await writeToggle(0x58, g);
  speedUnlocked=false; updateRegionToggle();
  log('speed lock: gear '+g+' sent -> back to normal drive mode.');
}
async function doRegionToggle(){ await doSpeedUnlock(); }   // primary button unlocks; the lock button locks
async function doRawSend(){
  if(!writeCh){ log('not connected'); return; }
  const bytes = parseHexFrame((($('raw-in')||{}).value)||'');
  if(!bytes){ log('raw: invalid hex'); return; }
  try{ await sendFrame(bytes); }catch(e){ log('raw send failed: '+(e&&e.message||e)); }
}
// Factory diagnostic: enter line-test (this un-gates the readback echo), then read the config-write
// lock (BE) and the live config (B9). NOTE: this is NOT side-effect-free. A0 sets the factory/auth
// session byte 0x208c38 (verified in the meter firmware, FUN_08019f7c) and enters line-test (the
// display goes dark); the exit path (A0 00) very likely triggers a reset. It writes no config, but it
// is not a passive read. Use only when you want the controller config-lock state.
async function doDiag(){
  if(!writeCh){ log('not connected'); return; }
  log('--- diagnose (line-test): A0 01 -> BE -> B9 -> A0 00 ---');
  log('note: A0 enters factory line-test (display goes dark, sets the factory/auth state); exit A0 00 likely resets the meter');
  try{
    await sendFrame(factoryFrame(0xA0,[0x01]));   // enter BLE line-test -> readback replies now echo to BLE (display goes dark)
    await sleep(700);
    await sendFrame(factoryFrame(0xBE));          // read config-write lock (controller sub 0x2d)
    await sleep(1500);                            // async: reply arrives after the controller round-trip
    await sendFrame(factoryFrame(0xB9));          // read live config (controller sub 0x29)
    await sleep(1600);
  } finally {
    await sendFrame(factoryFrame(0xA0,[0x00]));   // ALWAYS exit line-test -> display back on
  }
  log('--- diagnose done (line-test exited; display back on) ---');
}


function onDisconnect(){ stopFaultPoll(); lastFault=null; connected=false; authed=false; autoReadDone=false; phase2Sent=false; afterAuthDone=false; lastMaxSpeed=null; detectedModel=null; detectedCaps=null; detectedSpeed=null; detectedSku=null; detectedBldcFw=null; writeCh=notifyCh=null; rx=[]; const mt=$('t-model'); if(mt) mt.textContent='-'; setStatus('disconnected'); log('disconnected'); refreshButtons(); resetSettings(); applyModelCaps(); resetTiles(); }
function disconnect(){ if(device&&device.gatt.connected) device.gatt.disconnect(); }

// The connect button stays disabled until we have something to authenticate with: a numeric account
// userId (needed by any bound scooter), a pasted auth frame, or the explicit unbound opt-in.
function hasAuthCreds(){
  const uid=(($('uid-in')&&$('uid-in').value)||'').trim();
  const hex=(($('authhex-in')&&$('authhex-in').value)||'').trim();
  const unbound=$('unbound')&&$('unbound').checked;
  return (/^\d+$/.test(uid) && parseInt(uid,10)>0) || hex.length>=8 || !!unbound;
}
function refreshButtons(){
  const on=connected;
  { const c=$('btn-conn'); if(c){ c.textContent = on ? t('btnDisconnect') : t('btnConnect'); c.disabled = false; } }   // userId is optional - Connect is always available
  { const b=$('btn-regiontoggle'); if(b) b.disabled=!on; }
  { const b=$('btn-speedlock'); if(b) b.disabled=!on; }
  { const b=$('btn-diag'); if(b) b.disabled=!on; }
  { const b=$('btn-raw'); if(b){ b.disabled=!on; const i=$('raw-in'); if(i) i.disabled=!on; } }
  SETTINGS.forEach(s=>{ const b=$(s.btn), sel=$(s.sel); if(b) b.disabled=!on; if(sel) sel.disabled=!on; });
}
// Forget the stored login: the userId, the extracted/pasted auth frame and the remembered scooter.
// Everything lives only in this browser's localStorage; nothing is on any server.
function clearStoredAuth(){
  ['navee.uid','navee.authhex','navee.device'].forEach(k=>{ try{ localStorage.removeItem(k); }catch(e){} });
  const u=$('uid-in'); if(u) u.value='';
  const ah=$('authhex-in'); if(ah) ah.value='';
  log(t('logCleared')||'stored userId / auth frame / remembered scooter deleted from this browser');
  if(!connected) refreshButtons();
}

// Extra settings: each row is a <select> plus a Set button. All opcodes/payloads are byte-exact
// from the app's own settings screens. `off` is the field's offset in the 0x70 param report; a row
// is only shown when the connected scooter actually reports that byte, so each model shows only the
// options it supports. `state` maps a reported byte to the select value.
const TOGGLE_STATE = v => (v ? 1 : 0);
const SETTINGS = [
  { key:'lock',   sel:'lock-in',   btn:'btn-locksel', off:null, capRow:true, send:v=>writeToggle(0x51,v), state:TOGGLE_STATE }, // Wegfahrsperre - universal, visibility owned by applyModelCaps
  { key:'zero',   sel:'zero-in',   btn:'btn-zero',   off:19, capRow:true, send:v=>writeStartSpeed(v), state:v=>Math.min(5,v) },  // Zero-Start - per-model, gated by applyModelCaps
  { key:'drive',  sel:'drive-in',  btn:'btn-drive',  off:26, send:v=>writeSub(0x6E,2,v), state:TOGGLE_STATE }, // Dual-Drive
  { key:'accel',  sel:'accel-in',  btn:'btn-accel',  off:null, send:v=>writeToggle(0x58,v) },                  // Normal 3 / Turbo 5
  { key:'ers',    sel:'ers-in',    btn:'btn-ers',    off:5,  send:v=>writeToggle(0x53,v), state:v=>v },        // Rekuperation
  { key:'limitc', sel:'limitc-in', btn:'btn-limitc', off:20, send:v=>writeLimitSpeed(v,true), state:v=>(v&0x7f) }, // Custom-Limit
  { key:'kmalg',  sel:'kmalg-in',  btn:'btn-kmalg',  off:6,  send:v=>writeToggle(0x56,v), state:v=>v },
  { key:'osc',    sel:'osc-in',    btn:'btn-osc',    off:39, send:v=>writeToggle(0x82,v), state:TOGGLE_STATE },
  { key:'tcs',    sel:'tcs-in',    btn:'btn-tcs',    off:11, send:v=>writeToggle(0x5F,v), state:TOGGLE_STATE },
  { key:'slope',  sel:'slope-in',  btn:'btn-slope',  off:37, send:v=>writeToggle(0x81,v), state:TOGGLE_STATE },
  { key:'cruise', sel:'cruise-in', btn:'btn-cruise', off:3,  capRow:true, send:v=>writeToggle(0x52,v), state:TOGGLE_STATE }, // Tempomat - per-model, gated by applyModelCaps
  { key:'lrange', sel:'lrange-in', btn:'btn-lrange', off:38, send:v=>writeSub(0x6F,7,v), state:TOGGLE_STATE },
  { key:'lowpow', sel:'lowpow-in', btn:'btn-lowpow', off:32, send:v=>writeSub(0x6F,5,v), state:TOGGLE_STATE },
  { key:'chlimit',sel:'chlimit-in',btn:'btn-chlimit',off:31, send:v=>writeSub(0x6F,4,v), state:v=>v },
  { key:'locktime',sel:'locktime-in',btn:'btn-locktime',off:34, send:v=>writeSub(0x6F,2,v), state:v=>v },
  { key:'tail',   sel:'tail-in',   btn:'btn-tail',   off:4,  send:v=>writeToggle(0x54,v), state:TOGGLE_STATE },
  { key:'alight', sel:'alight-in', btn:'btn-alight', off:8,  send:v=>writeToggle(0x57,v), state:TOGGLE_STATE },
  { key:'ambient',sel:'ambient-in',btn:'btn-ambient',off:10, send:v=>writeToggle(0x5E,v), state:TOGGLE_STATE },
  { key:'logo',   sel:'logo-in',   btn:'btn-logo',   off:23, send:v=>writeSub(0x6D,2,v), state:TOGGLE_STATE },
  { key:'dayrun', sel:'dayrun-in', btn:'btn-dayrun', off:24, send:v=>writeSub(0x6D,3,v), state:TOGGLE_STATE },
  { key:'tsound', sel:'tsound-in', btn:'btn-tsound', off:12, send:v=>writeToggle(0x60,v), state:TOGGLE_STATE },
  { key:'sound',  sel:'sound-in',  btn:'btn-sound',  off:21, send:v=>writeSound(v), state:v=>(v&0x7f) },
  { key:'unit',   sel:'unit-in',   btn:'btn-unit',   off:7,  send:v=>writeToggle(0x55,v), state:v=>(v?1:0) },
  { key:'prox',   sel:'prox-in',   btn:'btn-prox',   off:13, send:v=>writeToggle(0x61,v), state:TOGGLE_STATE },
  { key:'tyre',   sel:null,        btn:'btn-tyre',   off:null, send:()=>writeToggle(0x5A,1) },
];
// Reveal only the settings the scooter reports (data block p from a 0x70 report) and prefill them.
function applyReportToSettings(p){
  let any=false;
  SETTINGS.forEach(s=>{
    const row=$('row-'+s.key); if(!row) return;
    if(s.capRow){ if(s.off!=null && s.off<p.length){ const sel=$(s.sel); if(sel&&s.state) sel.value=String(s.state(p[s.off])); } return; } // visibility owned by applyModelCaps; prefill only
    if(s.off==null){ row.hidden=false; any=true; return; }   // no report field: show once connected
    if(s.off < p.length){ row.hidden=false; any=true; const sel=$(s.sel); if(sel&&s.state) sel.value=String(s.state(p[s.off])); }
    else row.hidden=true;
  });
  const empty=$('more-empty'); if(empty) empty.hidden=any;
}
function resetSettings(){ SETTINGS.forEach(s=>{ const row=$('row-'+s.key); if(row) row.hidden=true; }); const e=$('more-empty'); if(e) e.hidden=false; }

// Copy the log with the line endings the user's OS expects: CRLF on Windows (Notepad and friends
// only break on \r\n), plain LF on macOS/Linux. Falls back to a hidden textarea where the async
// clipboard API is unavailable.
function osNewline(){
  const p = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || navigator.userAgent || '';
  return /win/i.test(p) ? '\r\n' : '\n';
}
function copyLog(){
  const el=$('log'); if(!el) return;
  const text=(el.textContent||'').replace(/\r?\n/g, osNewline());
  const done=()=>{ const b=$('btn-copy-log'); if(b){ const o=b.textContent; b.textContent=t('btnCopied')||'OK'; setTimeout(()=>{ b.textContent=o; }, 1200); } };
  if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(text).then(done).catch(()=>fallbackCopy(text,done)); }
  else fallbackCopy(text, done);
}
function fallbackCopy(text, done){
  try{ const ta=document.createElement('textarea'); ta.value=text; ta.setAttribute('readonly',''); ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); if(done) done(); }catch(e){ log('copy failed'); }
}
function clearLog(){ const el=$('log'); if(el) el.textContent=''; }

function wireControls(){
  $('btn-conn').addEventListener('click', ()=> connected ? disconnect() : connect());
  { const b=$('btn-regiontoggle'); if(b) b.addEventListener('click', doRegionToggle); }
  { const b=$('btn-speedlock'); if(b) b.addEventListener('click', doSpeedLock); }
  { const b=$('btn-diag'); if(b) b.addEventListener('click', doDiag); }
  { const b=$('btn-raw'); if(b) b.addEventListener('click', doRawSend); }
  ['region-open-in','region-lock-in'].forEach(id=>{ const el=$(id); if(el) el.addEventListener('change', updateRegionToggle); });
  ['open-in','locked-in'].forEach(id=>{ const el=$(id); if(el) el.addEventListener('change', persistDrossel); });
  SETTINGS.forEach(s=>{ const b=$(s.btn); if(b) b.addEventListener('click', ()=>{ const el=s.sel?$(s.sel):null; s.send(el?(parseInt(el.value||'0',10)||0):0); }); });
  $('btn-copy-log').addEventListener('click', copyLog);
  $('btn-clear-log').addEventListener('click', clearLog);
  // Account userId: prefill from storage, remember on edit, and gate the connect button on it.
  // Smart paste: a whole login response -> pull the userId out of it; a pasted 0x30 auth frame ->
  // it is NOT the numeric userId (the id sits hex-encoded inside it), so route it to the Auth-frame
  // field instead of stripping it to garbage digits; anything else -> keep digits only (userId is a
  // 32-bit int, at most 10 digits).
  { const u=$('uid-in'); if(u){ try{ const s=localStorage.getItem('navee.uid'); if(s) u.value=s; }catch(e){}
      u.addEventListener('input', ()=>{
        const raw=u.value.trim();
        const f=parseHexFrame(raw);
        if(f && f.length>=9 && f[0]===0x55 && f[1]===0xAA && f[3]===0x30){   // an auth frame was pasted here by mistake
          const ah=$('authhex-in');
          if(ah){ ah.value=raw; const det=ah.closest&&ah.closest('details'); if(det) det.open=true; }
          u.value='';
          try{ localStorage.setItem('navee.uid',''); }catch(e){}
          log(t('logFrameToAuth') || 'auth frame detected -> moved to the Auth-frame field under Advanced. That frame is not the numeric userId.');
          if(!connected) refreshButtons();
          return;
        }
        const m=u.value.match(/user_?id["']?\s*[:=]\s*"?(\d{1,10})/i);
        const v = m ? m[1] : u.value.replace(/[^0-9]/g,'');
        if(v!==u.value) u.value=v;
        try{ localStorage.setItem('navee.uid', u.value.trim()); }catch(e){}
        if(!connected) refreshButtons();
      }); } }
  { const ah=$('authhex-in'); if(ah){ try{ const s=localStorage.getItem('navee.authhex'); if(s&&!ah.value) ah.value=s; }catch(e){}
      ah.addEventListener('input', ()=>{ try{ localStorage.setItem('navee.authhex', ah.value.trim()); }catch(e){} if(!connected) refreshButtons(); }); } }
  { const lf=$('log-in'); if(lf) lf.addEventListener('change', ()=>{ const file=lf.files&&lf.files[0]; handleLogFile(file); lf.value=''; }); }
  { const cl=$('btn-clearid'); if(cl) cl.addEventListener('click', e=>{ e.preventDefault(); clearStoredAuth(); }); }
  { const cb=$('unbound'); if(cb) cb.addEventListener('change', ()=>{ if(!connected) refreshButtons(); }); }
  // Reveal toggles: the userId / auth-frame fields are masked (type=password) so a screenshot does
  // not leak the account id; the checkbox flips the field visible on demand.
  document.querySelectorAll('.reveal-cb').forEach(cb=>{ cb.addEventListener('change', ()=>{ const inp=$(cb.dataset.reveal); if(inp) inp.type = cb.checked ? 'text' : 'password'; }); });
}

// ---------- language ----------
let lang='de';
const table = () => (window.I18N && window.I18N[lang]) || {};
function t(key){ const v=table()[key]; return (typeof v==='string') ? v : ''; }
function applyLang(){
  document.documentElement.lang=lang;
  document.querySelectorAll('[data-t]').forEach(n=>{ const v=t(n.getAttribute('data-t')); if(/[<&]/.test(v)) n.innerHTML=v; else n.textContent=v; }); // scan-ok: v is our own i18n string, only the guide link carries markup
  document.querySelectorAll('[data-t-ph]').forEach(n=> n.setAttribute('placeholder', t(n.getAttribute('data-t-ph'))));
  const g=$('link-guide'); if(g) g.href=docFile('GUIDE');
  const li=$('link-license'); if(li) li.href=docFile('LICENSE');
  const pr=$('link-privacy'); if(pr) pr.href=docFile('PRIVACY');
  const tm=$('link-trademarks'); if(tm) tm.href=docFile('TRADEMARKS');
  const ls=$('langs'); if(ls) ls.setAttribute('aria-label', t('langGroup'));
  const bv=$('build-ver'); if(bv) bv.textContent=t('buildLabel')+' '+BUILD;
  document.querySelectorAll('#langs button').forEach(b=> b.setAttribute('aria-pressed', String(b.dataset.lang===lang)));
  const st=$('status'); if(st) setStatus(st.dataset.state||'disconnected');
  const th=$('btn-theme'); if(th){ const dark=document.documentElement.getAttribute('data-theme')!=='light'; th.setAttribute('aria-label', t(dark?'themeToLight':'themeToDark')); th.title=th.getAttribute('aria-label'); }
  updateRegionToggle();
  refreshButtons();
  applyModelCaps();   // re-apply the model gating so the fn-model line + rows keep their state after a language switch
}
function initLang(){
  let saved=null; try{ saved=localStorage.getItem('navee.lang'); }catch(e){}
  if(saved==='de'||saved==='en') lang=saved;
  document.querySelectorAll('#langs button').forEach(b=> b.addEventListener('click', ()=>{ lang=b.dataset.lang; try{ localStorage.setItem('navee.lang',lang); }catch(e){} applyLang(); }));
}

// ---------- theme ----------
function applyTheme(dark){
  document.documentElement.setAttribute('data-theme', dark?'dark':'light');
  const b=$('btn-theme'); if(b){ b.textContent = dark?'☀':'☾'; b.setAttribute('aria-label', t(dark?'themeToLight':'themeToDark')); b.title=b.getAttribute('aria-label'); }
  try{ localStorage.setItem('navee.theme', dark?'dark':'light'); }catch(e){}
}
function initTheme(){
  let saved=null; try{ saved=localStorage.getItem('navee.theme'); }catch(e){}
  applyTheme(saved!=='light');
  const b=$('btn-theme'); if(b) b.addEventListener('click', ()=> applyTheme(document.documentElement.getAttribute('data-theme')==='light'));
}

// ---------- document viewer ----------
const DOC_TITLES = {
  'GUIDE.de.md':'footGuide','GUIDE.en.md':'footGuide',
  'PRIVACY.de.md':'footPrivacy','PRIVACY.md':'footPrivacy',
  'LICENSE.de.md':'footLicense','LICENSE.md':'footLicense',
  'TRADEMARKS.de.md':'footTrademarks','TRADEMARKS.md':'footTrademarks',
  'README.md':'footReadme',
};
const escHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const slug = s => s.toLowerCase().trim().replace(/[^\w\sÀ-ɏ-]/g,'').replace(/ /g,'-');
function mdToHtml(src){
  const inline = s => escHtml(s)
    .replace(/`([^`]+)`/g,'<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g,'<b>$1</b>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g,(all,text,href)=>{
      if(DOC_TITLES[href]) return `<a href="${href}" data-docfile="${href}">${text}</a>`;
      if(href.startsWith('#')) return `<a href="${href}" data-anchor="${href.slice(1)}">${text}</a>`;
      return `<a href="${href}" target="_blank" rel="noopener">${text}</a>`;
    });
  const lines=String(src).replace(/\r\n?/g,'\n').split('\n');
  const out=[]; let listKind=null, li=null, para=[], inFence=false;
  const sink=()=> (li?li.parts:out);
  const flushPara=()=>{ if(para.length){ sink().push('<p>'+inline(para.join(' '))+'</p>'); para=[]; } };
  const closeNested=()=>{ if(li&&li.nested){ li.parts.push('</ul>'); li.nested=false; } };
  const closeLi=()=>{ if(!li) return; flushPara(); closeNested(); out.push('<li>'+li.parts.join('\n')+'</li>'); li=null; };
  const closeList=()=>{ closeLi(); if(listKind){ out.push('</'+listKind+'>'); listKind=null; } };
  const block=()=>{ flushPara(); closeList(); };
  const openList=kind=>{ flushPara(); if(listKind!==kind){ closeList(); out.push('<'+kind+'>'); listKind=kind; } else closeLi(); };
  const cells=l=> l.replace(/^\||\|$/g,'').split('|').map(c=>c.trim());
  for(let i=0;i<lines.length;i++){
    const l=lines[i], body=l.trim(), indented=/^ {2,}\S/.test(l);
    if(inFence){ if(body.startsWith('```')){ sink().push('</code></pre>'); inFence=false; } else sink().push(escHtml(l)); continue; }
    if(body.startsWith('```')){ if(li){ flushPara(); closeNested(); } else block(); sink().push('<pre><code>'); inFence=true; continue; }
    if(body===''){ if(li && /^ {2,}\S/.test(lines[i+1]||'')) flushPara(); else block(); continue; }
    if(/^(-{3,}|\*{3,}|_{3,})\s*$/.test(body)){ block(); out.push('<hr>'); continue; }
    if(body.startsWith('|') && /^\|[\s:|-]+\|?\s*$/.test((lines[i+1]||'').trim())){
      if(li){ flushPara(); closeNested(); } else block();
      sink().push('<div class="doc-table"><table><thead><tr>'+cells(body).map(c=>'<th>'+inline(c)+'</th>').join('')+'</tr></thead><tbody>');
      i++;
      while(i+1<lines.length && lines[i+1].trim().startsWith('|')) sink().push('<tr>'+cells(lines[++i].trim()).map(c=>'<td>'+inline(c)+'</td>').join('')+'</tr>');
      sink().push('</tbody></table></div>'); continue;
    }
    let m;
    if((m=body.match(/^(#{1,4})\s+(.*)$/))){ block(); const n=m[1].length; out.push(`<h${n} id="${slug(m[2])}">${inline(m[2])}</h${n}>`); continue; }
    if((m=body.match(/^>\s?(.*)$/))){ if(li){ flushPara(); closeNested(); } else block(); sink().push('<blockquote>'+inline(m[1])+'</blockquote>'); continue; }
    if(indented && li && (m=body.match(/^[-*]\s+(.*)$/))){ flushPara(); if(!li.nested){ li.parts.push('<ul class="nested">'); li.nested=true; } li.parts.push('<li>'+inline(m[1])+'</li>'); continue; }
    if((m=body.match(/^[-*]\s+(.*)$/)) && !indented){ openList('ul'); li={parts:[inline(m[1])],nested:false}; continue; }
    if((m=body.match(/^\d+\.\s+(.*)$/)) && !indented){ openList('ol'); li={parts:[inline(m[1])],nested:false}; continue; }
    if(li && !indented) closeList();
    if(li) closeNested();
    para.push(body);
  }
  if(inFence) sink().push('</code></pre>');
  block();
  return out.join('\n').replace(/<pre><code>\n/g,'<pre><code>');
}
const docCache={};
const docFile = name => name==='GUIDE' ? `GUIDE.${lang}.md` : name==='README' ? 'README.md' : (lang==='de' ? `${name}.de.md` : `${name}.md`);
function openDoc(name,anchor,titleKey){ openDocFile(docFile(name),anchor,titleKey); }
function openDocFile(file,anchor,titleKey){
  const dlg=$('doc'), body=$('doc-body'); if(!dlg||!body) return;
  const mark=(lang==='de' && !file.includes('.de.') && file!=='README.md') ? ' '+t('docEnglish') : '';
  $('doc-title').textContent=(t(titleKey||DOC_TITLES[file]||'')||file)+mark;
  if(typeof dlg.showModal==='function') dlg.showModal();
  const show=html=>{
    body.innerHTML=html; // scan-ok: html is our own markdown rendered by mdToHtml, which escapes every source char first
    const h1=body.querySelector('h1'); if(h1){ $('doc-title').textContent=h1.textContent.trim()+mark; h1.remove(); }
    body.scrollTop=0;
    if(anchor){ const tgt=body.querySelector('#'+(window.CSS&&CSS.escape?CSS.escape(anchor):anchor)); if(tgt) body.scrollTop=tgt.offsetTop-body.offsetTop; }
  };
  if(docCache[file]){ show(docCache[file]); return; }
  body.innerHTML='<p>'+escHtml(t('docLoading'))+'</p>'; // scan-ok: literal plus escHtml()
  fetch(file+'?v='+BUILD).then(r=>{ if(!r.ok) throw new Error(r.status+' '+r.statusText); return r.text(); })
    .then(txt=>{ docCache[file]=mdToHtml(txt); show(docCache[file]); })
    .catch(e=>{ body.innerHTML='<p>'+escHtml(t('docFail'))+'</p><pre>'+escHtml(file+': '+(e&&e.message?e.message:e))+'</pre>'; }); // scan-ok: literals plus escHtml()
}
function wireDocViewer(){
  document.addEventListener('click', e=>{
    if(!e.target.closest) return;
    const jump=e.target.closest('[data-anchor]');
    if(jump){ e.preventDefault(); const body=$('doc-body'); const tgt=body&&body.querySelector('#'+CSS.escape(jump.getAttribute('data-anchor'))); if(tgt) body.scrollTop=tgt.offsetTop-body.offsetTop; return; }
    const a=e.target.closest('[data-doc], [data-docfile]'); if(!a) return;
    e.preventDefault();
    { const h=$('help'); if(h&&h.open&&h.close) h.close(); }   // if a doc link was clicked inside the help popup, close it first
    const file=a.getAttribute('data-docfile'), titleKey=a.getAttribute('data-t')||'';
    if(file) openDocFile(file,'',titleKey); else openDoc(a.getAttribute('data-doc'),'',titleKey);
  });
  ['doc-x','doc-close'].forEach(id=>{ const b=$(id); if(b) b.addEventListener('click', ()=>{ const d=$('doc'); if(d) d.close(); }); });
}

// ---------- help modal ----------
const HELP = {
  fn:       ['fnHelpTitle', 'fnHelp'],
  logupload:['logUploadTitle', 'logUploadHelp'],
  more:    ['moreTitle', 'moreHelp'],
  country: ['s4Title', 'countryHelp'],
  account: ['accountTitle', 'accountHelp'],
  authhex: ['authhexTitle', 'authhexHelp'],
  disclaimer: ['footDisclaimer', 'disclaimerText'],
};
function openHelp(key){ const m=HELP[key]; if(!m) return; const dlg=$('help'); if(!dlg) return; $('help-title').textContent=t(m[0]); $('help-body').innerHTML=t(m[1]); if(typeof dlg.showModal==='function') dlg.showModal(); } // scan-ok: HELP is a static developer-authored map, m[1] is always one of our own i18n body strings (moreHelp/countryHelp/accountHelp/authhexHelp/disclaimerText), no user input reaches it; same trusted-i18n case as the data-t line above
function closeHelp(){ const d=$('help'); if(d&&d.close) d.close(); }
function wireHelp(){
  document.querySelectorAll('.help-btn').forEach(b=> b.addEventListener('click', ()=> openHelp(b.getAttribute('data-help'))));
  ['help-x','help-close'].forEach(id=>{ const b=$(id); if(b) b.addEventListener('click', closeHelp); });
  const dis=$('link-disclaimer'); if(dis) dis.addEventListener('click', e=>{ e.preventDefault(); openHelp('disclaimer'); });
  document.addEventListener('click', e=>{ if(e.target.closest && e.target.closest('[data-open-disclaimer]')){ e.preventDefault(); openHelp('disclaimer'); } });
}

// ---------- home-screen shortcuts (deep link ?do=fast|slow, like sf-unlock) ----------
// A shortcut opens the page with ?do=fast (unlock/open) or ?do=slow (throttle). The page reconnects
// to the last granted scooter via getDevices() (no chooser) and runs the action after auth.
let pendingDeepAction=null;
function parseDeepLink(){
  try{
    let a=(new URLSearchParams(location.search).get('do')||'').toLowerCase();
    if(!a&&location.hash) a=(new URLSearchParams(location.hash.replace(/^#/,'')).get('do')||'').toLowerCase();
    if(a==='unlock'||a==='fast') pendingDeepAction='unlock';       // open
    else if(a==='lock'||a==='slow') pendingDeepAction='lock';      // throttle
    if(pendingDeepAction) log('shortcut: '+pendingDeepAction+' requested');
  }catch(e){}
}
async function maybeRunDeepAction(){
  if(!pendingDeepAction||!writeCh) return;
  const a=pendingDeepAction; pendingDeepAction=null;
  log('shortcut: '+a);
  if(a==='unlock'){ await doSpeedUnlock(); }
  else { await doSpeedLock(); }
}
async function tryAutoReconnect(){
  if(!pendingDeepAction) return;                 // only auto-reconnect when a shortcut asked for it
  if(!navigator.bluetooth||!navigator.bluetooth.getDevices) return;
  let devs; try{ devs=await navigator.bluetooth.getDevices(); }catch(e){ return; }
  if(!devs||!devs.length){ log('shortcut: no remembered scooter, connect once manually first'); return; }
  let savedId=null; try{ savedId=localStorage.getItem('navee.device'); }catch(e){}
  const dev=(savedId&&devs.find(d=>d.id===savedId)) || devs.find(d=>(d.name||'').indexOf('NAVEE')>=0) || null;
  if(!dev){ log('shortcut: remembered scooter not in range'); return; }
  try{ log('auto-reconnect: '+(dev.name||dev.id)); await connectDevice(dev); }
  catch(e){ setStatus('disconnected'); log('auto-reconnect failed: '+(e&&e.message?e.message:e)); }
}

wireControls();
loadDrossel();
initLang();
initTheme();
wireDocViewer();
wireHelp();
applyLang();
parseDeepLink();
tryAutoReconnect();
log('Tbe Navee '+BUILD);
if(!('bluetooth' in navigator)) log('Web Bluetooth not available - use Chrome (Android/desktop) or Bluefy (iOS).');

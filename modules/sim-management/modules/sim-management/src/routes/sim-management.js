import express from 'express';
import { Parser } from 'json2csv';
import PDFDocument from 'pdfkit';

const ROLES = new Set(['admin','it_support','customer_service','viewer']);
const WRITERS = new Set(['admin','it_support','customer_service']);
const clean = (v,n=180) => String(v??'').trim().slice(0,n);
const monthDate = v => /^\d{4}-\d{2}$/.test(v||'') ? `${v}-01` : null;
const error = (res,status,message) => res.status(status).json({error:message});

export function createSimManagementRouter({supabase,requireAuth,getRole,getActor}) {
 if(!supabase||!requireAuth) throw new Error('Existing Supabase client and requireAuth are required');
 const router=express.Router();
 router.use(requireAuth);
 const role=req=>{const r=getRole?.(req)??req.user?.role;return ROLES.has(r)?r:'viewer'};
 const actor=req=>getActor?.(req)??({id:req.user?.id??null,email:req.user?.email??null});
 const writer=req=>WRITERS.has(role(req));
 const audit=async(req,sim_id,action,details={})=>{const a=actor(req);await supabase.from('sim_audit_logs').insert({sim_id,action,actor_id:a.id,actor_email:a.email,details});};

 router.get('/health',(req,res)=>res.json({ok:true,role:role(req)}));
 router.get('/dashboard',async(req,res)=>{
  const [s,r]=await Promise.all([supabase.from('sim_cards').select('id,status'),supabase.from('sim_recharges').select('sim_id').eq('recharge_month',`${new Date().toISOString().slice(0,7)}-01`)]);
  if(s.error||r.error)return error(res,500,'Dashboard unavailable');
  const active=s.data.filter(x=>x.status==='active').length;
  res.json({total:s.data.length,active,recharged:r.data.length,pending:Math.max(0,active-r.data.length)});
 });
 router.get('/sims',async(req,res)=>{
  let q=supabase.from('sim_cards').select('*').order('created_at',{ascending:false}).limit(1000);
  const term=clean(req.query.q,80);
  if(term) q=q.or(`phone_number.ilike.%${term}%,imsi.ilike.%${term}%,iccid.ilike.%${term}%,kp_number.ilike.%${term}%,mn_number.ilike.%${term}%,shop_name.ilike.%${term}%,location.ilike.%${term}%`);
  if(['active','inactive','suspended','retired'].includes(req.query.status))q=q.eq('status',req.query.status);
  const {data,error:e}=await q;if(e)return error(res,500,'Could not retrieve SIMs');res.json(data);
 });
 router.post('/sims',async(req,res)=>{
  if(!writer(req))return error(res,403,'Insufficient permissions');
  const b=req.body||{},phone=clean(b.phone_number,24).replace(/[\s()-]/g,''),imsi=clean(b.imsi,20).replace(/\s/g,''),iccid=clean(b.iccid,24).replace(/\s/g,'');
  if(!/^\+?[0-9]{9,15}$/.test(phone)||!/^[0-9]{14,16}$/.test(imsi)||!/^[0-9]{18,22}$/.test(iccid))return error(res,400,'Check phone, IMSI and ICCID formats');
  const a=actor(req);
  const payload={phone_number:phone,imsi,iccid,network_provider:clean(b.network_provider,40)||'Safaricom',kp_number:clean(b.kp_number,40)||null,mn_number:clean(b.mn_number,40)||null,shop_name:clean(b.shop_name,120)||null,location:clean(b.location,120)||null,activation_date:b.activation_date||null,status:['active','inactive','suspended','retired'].includes(b.status)?b.status:'active',notes:clean(b.notes,500)||null,created_by:a.id,created_by_email:a.email,updated_by:a.id};
  const {data,error:e}=await supabase.from('sim_cards').insert(payload).select().single();
  if(e?.code==='23505')return error(res,409,'Duplicate phone number, IMSI or ICCID');
  if(e)return error(res,500,'SIM registration failed');
  await audit(req,data.id,'sim.created',{kp_number:data.kp_number});res.status(201).json(data);
 });
 router.post('/recharges',async(req,res)=>{
  if(!writer(req))return error(res,403,'Insufficient permissions');
  const b=req.body||{},month=monthDate(clean(b.month,7)),amount=Number(b.amount_kes);
  if(!b.sim_id||!month||!Number.isFinite(amount)||amount<0)return error(res,400,'SIM, month and valid amount are required');
  const a=actor(req);
  const {data,error:e}=await supabase.from('sim_recharges').insert({sim_id:b.sim_id,recharge_month:month,amount_kes:amount,transaction_reference:clean(b.transaction_reference,100)||null,notes:clean(b.notes,500)||null,recorded_by:a.id,recorded_by_email:a.email}).select().single();
  if(e?.code==='23505')return error(res,409,'This SIM is already marked recharged for that month');
  if(e)return error(res,500,'Recharge record failed');
  await audit(req,data.sim_id,'recharge.recorded',{month:b.month,amount_kes:amount});res.status(201).json(data);
 });
 router.get('/recharges',async(req,res)=>{
  let q=supabase.from('sim_recharges').select('*,sim_cards(phone_number,kp_number,mn_number,shop_name)').order('recharge_month',{ascending:false}).limit(1000);
  if(req.query.month){const m=monthDate(clean(req.query.month,7));if(!m)return error(res,400,'Month format must be YYYY-MM');q=q.eq('recharge_month',m);}
  const {data,error:e}=await q;if(e)return error(res,500,'Recharge history unavailable');res.json(data);
 });
 router.get('/export.csv',async(req,res)=>{
  const [s,r]=await Promise.all([supabase.from('sim_cards').select('*').order('created_at',{ascending:false}),supabase.from('sim_recharges').select('sim_id,recharge_month')]);
  if(s.error||r.error)return error(res,500,'CSV export failed');
  const rows=s.data.map(x=>({...x,latest_recharge:r.data.filter(y=>y.sim_id===x.id).sort((a,b)=>b.recharge_month.localeCompare(a.recharge_month))[0]?.recharge_month||''}));
  const csv=new Parser({fields:['phone_number','imsi','iccid','network_provider','kp_number','mn_number','shop_name','location','activation_date','status','latest_recharge']}).parse(rows);
  res.type('text/csv').attachment('moto-nzuri-sim-register.csv').send(csv);
 });
 router.get('/export.pdf',async(req,res)=>{
  const {data,error:e}=await supabase.from('sim_cards').select('*').order('created_at',{ascending:false});if(e)return error(res,500,'PDF export failed');
  res.type('application/pdf').attachment('moto-nzuri-sim-register.pdf');const pdf=new PDFDocument({size:'A4',layout:'landscape',margin:28});pdf.pipe(res);
  pdf.fontSize(18).text('MOTO NZURI — SIM REGISTER');pdf.moveDown();pdf.fontSize(8).text(`Generated ${new Date().toLocaleString()} | ${data.length} records`);pdf.moveDown();
  const cols=[['Phone',85],['KP / MN',85],['IMSI',110],['ICCID',145],['Network',75],['Shop / location',190],['Status',55]];
  const header=()=>{let x=28,y=pdf.y;pdf.font('Helvetica-Bold').fontSize(8);for(const [t,w] of cols){pdf.text(t,x,y,{width:w});x+=w;}pdf.moveTo(28,y+14).lineTo(810,y+14).stroke();pdf.y=y+19;};header();
  for(const s of data){if(pdf.y>540){pdf.addPage({size:'A4',layout:'landscape',margin:28});header();}let x=28,y=pdf.y;const vals=[s.phone_number,`${s.kp_number||'-'} / ${s.mn_number||'-'}`,s.imsi,s.iccid,s.network_provider,s.shop_name||s.location||'-',s.status];pdf.font('Helvetica').fontSize(7);vals.forEach((v,i)=>{pdf.text(String(v??'-'),x,y,{width:cols[i][1],height:24,ellipsis:true});x+=cols[i][1];});pdf.y=y+27;}pdf.end();
 });
 return router;
}

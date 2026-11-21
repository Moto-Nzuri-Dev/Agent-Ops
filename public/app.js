const form=document.querySelector("#shopForm");
const statusBox=document.querySelector("#status");
const submitButton=document.querySelector("#submitButton");
const submitNormal=document.querySelector("#submitNormal");
const submitLoading=document.querySelector("#submitLoading");
const gpsStatus=document.querySelector("#gpsStatus");
const MAX_BYTES=5*1024*1024;

const visitDate=document.querySelector("#visitDate");
visitDate.value=new Date().toISOString().slice(0,10);

function showStatus(message,type="error"){statusBox.textContent=message;statusBox.className=`status ${type}`;statusBox.classList.remove("hidden");statusBox.scrollIntoView({behavior:"smooth",block:"nearest"})}
function clearStatus(){statusBox.textContent="";statusBox.className="status hidden"}

let gpsTimer=null,gpsAttempt=0;
function captureGps(){
  if(!navigator.geolocation){gpsStatus.textContent="GPS is not supported on this device.";return}
  gpsStatus.textContent="Capturing shop coordinates…";
  navigator.geolocation.getCurrentPosition(p=>{
    document.querySelector("#latitude").value=p.coords.latitude.toFixed(7);
    document.querySelector("#longitude").value=p.coords.longitude.toFixed(7);
    gpsStatus.textContent=`GPS captured. Accuracy ±${Math.round(p.coords.accuracy)}m.`;
    clearTimeout(gpsTimer);
  },e=>{
    gpsStatus.textContent=e.code===1?"Location permission was denied. You can use Capture GPS to try again.":"GPS attempt failed. Retrying automatically if another attempt is scheduled.";
    scheduleGps();
  },{enableHighAccuracy:true,timeout:12000,maximumAge:0});
}
function scheduleGps(){
  const delays=[15000,30000,60000];
  if(gpsAttempt>=delays.length)return;
  const delay=delays[gpsAttempt++];
  gpsTimer=setTimeout(captureGps,delay);
}
document.querySelector("#getLocation").addEventListener("click",()=>{clearTimeout(gpsTimer);captureGps()});
scheduleGps();

function bindFile(inputId,previewId){
  const input=document.querySelector(inputId), preview=document.querySelector(previewId);
  input.addEventListener("change",()=>{
    const file=input.files[0];
    if(!file){preview.textContent="";preview.classList.add("hidden");return}
    if(!/^image\/(jpeg|png|webp)$/.test(file.type)){input.value="";preview.classList.add("hidden");showStatus("Photos must be JPG, PNG or WEBP.");return}
    if(file.size>MAX_BYTES){input.value="";preview.classList.add("hidden");showStatus("Each photo must be 5 MB or less.");return}
    preview.textContent=`Selected: ${file.name} (${(file.size/1024/1024).toFixed(2)} MB)`;preview.classList.remove("hidden");
  });
}
bindFile("#photo1","#photo1Preview");bindFile("#photo2","#photo2Preview");

function compressImage(file){
  return new Promise((resolve,reject)=>{
    const reader=new FileReader();
    reader.onerror=()=>reject(new Error("Could not read the photo."));
    reader.onload=()=>{
      const img=new Image();
      img.onerror=()=>reject(new Error("Could not process the photo."));
      img.onload=()=>{
        const maxWidth=1600; const scale=Math.min(1,maxWidth/img.width);
        const canvas=document.createElement("canvas"); canvas.width=Math.max(1,Math.round(img.width*scale)); canvas.height=Math.max(1,Math.round(img.height*scale));
        const ctx=canvas.getContext("2d"); ctx.drawImage(img,0,0,canvas.width,canvas.height);
        canvas.toBlob(blob=>blob?resolve(blob):reject(new Error("Photo compression failed.")),"image/jpeg",0.82);
      };
      img.src=reader.result;
    }; reader.readAsDataURL(file);
  });
}

function blobToBase64(blob){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onerror=()=>reject(new Error("Could not prepare photo."));reader.onload=()=>resolve(String(reader.result).split(",")[1]||"");reader.readAsDataURL(blob)})}

async function upload(file){
  if(!file)return null;
  if(!/^image\/(jpeg|png|webp)$/.test(file.type))throw new Error("Photos must be JPG, PNG or WEBP.");
  if(file.size>MAX_BYTES)throw new Error("Each photo must be 5 MB or less.");
  const blob=await compressImage(file);
  if(blob.size>MAX_BYTES)throw new Error("The compressed photo is still above the 5 MB limit.");
  const data=await blobToBase64(blob);
  const response=await fetch("/api/photo",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({filename:file.name.replace(/\.[^.]+$/,".jpg"),contentType:"image/jpeg",data})});
  const json=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(json.error||"Photo upload failed.");
  return json.path;
}

form.addEventListener("submit",async event=>{
  event.preventDefault(); clearStatus();
  if(!form.reportValidity())return;
  const p1=document.querySelector("#photo1").files[0],p2=document.querySelector("#photo2").files[0];
  submitButton.disabled=true;submitNormal.classList.add("hidden");submitLoading.classList.remove("hidden");
  try{
    const photo1Path=await upload(p1);
    const photo2Path=p2?await upload(p2):null;
    const fd=new FormData(form);
    if(!fd.get("latitude")||!fd.get("longitude"))throw new Error("Capture the shop GPS location first.");
    const payload={shop_name:fd.get("shopName"),kp:fd.get("kp"),location:fd.get("location"),latitude:Number(fd.get("latitude")),longitude:Number(fd.get("longitude")),agent_name:fd.get("agentName"),phone_number:fd.get("phoneNumber"),whatsapp_number:fd.get("whatsappNumber"),alternative_number:fd.get("alternativeNumber"),visit_date:fd.get("visitDate"),is_selling:fd.get("is_selling")===true||fd.get("is_selling")==="true",needs_machine:fd.get("needs_machine")===true||fd.get("needs_machine")==="true",photo1_path:photo1Path,photo2_path:photo2Path};
    const response=await fetch("/api/submit",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    const json=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(json.error||"Submission failed.");
    form.reset();visitDate.value=new Date().toISOString().slice(0,10);document.querySelector("#photo1Preview").classList.add("hidden");document.querySelector("#photo2Preview").classList.add("hidden");document.querySelector("#latitude").value="";document.querySelector("#longitude").value="";gpsStatus.textContent="Capture the shop coordinates using the device location.";
    showStatus("Registration submitted successfully.","success");
  }catch(error){showStatus(error.message||"Submission failed. Please try again.")}finally{submitButton.disabled=false;submitNormal.classList.remove("hidden");submitLoading.classList.add("hidden")}
});

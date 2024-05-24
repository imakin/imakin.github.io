
const storage_hashid = "anote";

function el(selector) {
    return document.querySelector(selector);
}
function els(selector){
    return document.querySelectorAll(selector);
}

const divlog = el("#log");
const tx = el("#anote_content");
tx.style.height = (tx.scrollHeight) + "px";
tx.style.overflowY = "hidden";

tx.addEventListener("input", OnInput, false);
el("#scroller").addEventListener("click", refresh_height, false);


function refresh_height() {
    tx.style.height = "auto";
    tx.style.height = (tx.scrollHeight) + "px";
    divlog.innerHTML = el("#password").offsetTop;
    el("#mainform").style.maxHeight = (36 + el("#password").offsetTop - 10) + "px";
}

function OnInput() {
    document.body.classList.add('modified');
}

function anote_redraw_content(encrypteddata, decrypt_password) {
    decryptblake2s(encrypteddata, decrypt_password, unpadhalf).then(function(text){
        tx.value = text;
        refresh_height();
    });
}
function downloadtext(text, filename){
    var blob = new Blob([text], {type: "application/octet-stream"});
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
}
function anote_load_local(password) {
    divlog.innerHTML = 'loading step 1/3';
    localhashblake2s(password,password+password).then(function(hashed_password) {
        divlog.innerHTML = 'loading step 2/3';
        //load to server
        console.log('nih: ',hashed_password);
        const r = new FileReader();
        r.addEventListener("load",()=>{
            anote_redraw_content(r.result, hashed_password);
        });
        r.readAsText(el('#openfile').files[0]);

    });
    
    
}
function anote_save_local(password) {
    divlog.innerHTML = 'saving step 1/4';
    localhashblake2s(password,password+password).then(function(hashed_password) {
        divlog.innerHTML = 'saving step 2/4';
        var prefix_padding = ((new Date()).toString().split('')).map(value => ({ value, sort: Math.random() }))
                                .sort((a, b) => a.sort - b.sort)
                                .map(({ value }) => value).join('');
        encryptblake2s(prefix_padding+tx.value, hashed_password, padhalf).then(function(encrypted_hexstring) {
            divlog.innerHTML = 'saving step 3/4';
            console.log("ini yg mau disimpen",encrypted_hexstring);
            console.log("pw nya "+hashed_password);
            downloadtext(encrypted_hexstring, "anote.enc");
        });
    });
}
function anote_load_numpang(serverdomain){
    divlog.innerHTML = 'loading step 1/6';
    decryptblake2s(
        "1fb7e3edcc26ae32cbe47d52fc40728487704c72c751191a3b3fb8186edebd02d8e8de8c963e6bfbcd00ea735b0830b35a01bfc967bcc16f22d0c0939d9221e83185f679a10a074ac74a225c726b2b62aa06cb35cef7c9840595ac80f281362a2ebb33603f830b72c83828ecc02287f99de34d939f8a202af21c4d89e2bf802b2f766f8acd3330c0674c67eccd247b6a5e89da71f81691e7197fcb5a6a087043",
        serverdomain,
        unpadhalf
    ).then(function(enctxt){
        divlog.innerHTML = 'loading step 2/6';
        fetch(enctxt).then(function(resp){
            divlog.innerHTML = 'loading step 3/6';
            resp.text().then(function(encrypted_data){
                divlog.innerHTML = 'loading step 4/6';
                password = el('#password').value;
                localhashblake2s(password,password+password).then(function(hashed_password) {
                    divlog.innerHTML = 'loading step 5/6';
                    anote_redraw_content(encrypted_data, hashed_password);
                });
            });
        });
    });
}

el('#openfile').addEventListener('change',()=>{
    anote_load_local(el('#password').value);
});
el('#savefile').addEventListener('click',()=>{
    anote_save_local(el('#password').value);
});
el('#reload').addEventListener('click',()=>{
    anote_load_local(el('#password').value);
});
el('#loadnumpang').addEventListener('click',()=>{
    anote_load_numpang(el('#serverdomain').value);
});

Array.from(els('#password, #serverdomain')).forEach(el=>{
    el.addEventListener('focus',e=>{
        e.currentTarget.type = 'text';
    })
});
Array.from(els('#password, #serverdomain')).forEach(el=>{
    el.addEventListener('blur',e=>{
        e.currentTarget.type = 'password';
    })
});

function ready(fn) {
    if (document.readyState != 'loading'){
        fn();
    } else {
        document.addEventListener('DOMContentLoaded', fn);
    }
}
ready(refresh_height());

// Native KodeBlue case/fleet discussion. Traffic collectors are optional evidence.
"use strict";
window.KodeBlueWarRoom = (() => {
  const roles = [["responder", "Responder"], ["reviewer", "Reviewer"], ["learner", "Learner"], ["operator", "Operator"]];
  let host=null,context={},servers=[],rooms=[],roomID="",draft=false,timer=null,request=0,epoch=0,busy=false,signature="",lead="",selected=new Map(),view=null;
  const eligible=s=>s.enrolled&&!s.revoked&&s.status?.supports_war_room&&s.status?.models_enabled&&s.status?.accepts_messages;
  const name=id=>servers.find(s=>s.id===id)?.name||id;
  function query(){const q=new URLSearchParams();if(context.server_id)q.set("server_id",context.server_id);if(context.case_id)q.set("case_id",context.case_id);if(roomID)q.set("selected",roomID);return q;}
  function current(){return rooms.find(r=>r.id===roomID);}
  function nativeLink(server,id){return `#/s/${enc(server)}${id?`/t/${enc(id)}`:""}`;}
  function note(message,bad=false){if(view){view.comp.setNote(message,bad);view.status.textContent=message;view.status.classList.toggle("bad",bad);view.status.hidden=!bad&&(!current()||current().status==="active"&&!current().error);}}
  function participantChips(room){
    const people=room?[room.lead,...room.participants]:[{server_id:lead,role:"investigator"},...Array.from(selected.values())];
    clear(view.chips);const sameServer=new Set(people.filter(p=>p.server_id).map(p=>p.server_id)).size===1;
    for(const person of people){if(!person.server_id)continue;const role=person.role==="investigator"?"Investigator":roles.find(r=>r[0]===person.role)?.[1]||"Agent";
      view.chips.append(h("span",{class:"chip",title:`${role} on ${name(person.server_id)} · read-only turn`},ic("bot",11),h("span",{class:"chip-l"},sameServer?role:`${role} · ${name(person.server_id)}`)));
    }
  }
  function roster(room){
    clear(view.rosterBody);
    const leadSelect=h("select",{class:"sel","aria-label":"Investigator server",disabled:!!room,on:{change:()=>{lead=leadSelect.value;participantChips(null);updateSend();}}},
      servers.filter(s=>s.enrolled&&!s.revoked).map(s=>h("option",{value:s.id,disabled:!eligible(s)},s.name+(eligible(s)?"":" · unavailable"))));
    leadSelect.value=room?.lead.server_id||lead;
    view.rosterBody.append(h("label",{class:"wr-lead"},"Investigator",leadSelect));
    for(const server of servers.filter(s=>s.enrolled&&!s.revoked)){
      const choices=roles.map(([role,label])=>{const key=`${server.id}:${role}`,included=room?room.participants.some(p=>p.server_id===server.id&&p.role===role):selected.has(key);
        const check=h("input",{type:"checkbox",checked:included,disabled:!!room||!eligible(server),"aria-label":`${label} on ${server.name}`});
        check.addEventListener("change",()=>{if(check.checked){if(selected.size>=4){check.checked=false;note("Choose up to four specialist turns.",true);return;}selected.set(key,{server_id:server.id,role});}else selected.delete(key);participantChips(null);});
        return h("label",{class:"wr-role-choice"},check,label);
      });
      view.rosterBody.append(h("div",{class:"wr-agent-row"},h("div",null,ic("server",12)," ",server.name,eligible(server)?null:h("span",{class:"faint small"}," · Update / model unavailable")),h("div",{class:"wr-role-grid"},choices)));
    }
    view.rosterBody.append(h("p",{class:"small faint"},"Each selected role contributes a separate read-only turn using its normal model and instructions. Running response and learning sessions keep their ownership."));
  }
  function paint(room){
    participantChips(room);roster(room);
    clear(view.history).append(...rooms.map(r=>h("option",{value:r.id},(r.case?`Case #${r.case.id} · `:"")+(r.entries[0]?.text.slice(0,45)||"Investigation"))));
    if(!room)view.history.prepend(h("option",{value:""},"New investigation"));view.history.value=roomID;
    view.pause.hidden=!room||["complete","ended"].includes(room.status);view.pause.textContent=room?.status==="paused"?"Resume":"Pause";view.end.hidden=!room||room.status==="ended";
    const sig=JSON.stringify(room||null);
    if(sig!==signature){signature=sig;const atBottom=view.chat.scrollHeight-view.chat.scrollTop-view.chat.clientHeight<70;
      clear(view.chat);
      if(!room)view.chat.append(h("div",{class:"tp-empty"},h("p",null,context.case_id?`Discuss case #${context.case_id} with the relevant agents.`:context.server_id?`Investigate activity on ${name(context.server_id)}.`:"Connect the evidence across your monitored infrastructure."),h("p",{class:"faint"},"Ask a question. The Investigator opens, selected agents answer in turn, then the Investigator concludes. Containers, services, host activity and network events belong to the same investigation.")));
      else for(const entry of room.entries){
        if(entry.kind==="pass"||entry.kind==="gap"){view.chat.append(h("div",{class:"turn sys"+(entry.kind==="gap"?" bad":"")},entry.text));continue;}
        const label=h("div",{class:"ulbl"},ic(entry.kind==="admin"?"user":"bot",11),entry.speaker,h("span",{class:"ut"},clock(entry.at)));
        if(entry.kind==="admin")view.chat.append(h("div",{class:"turn"},h("div",{class:"ubox"},label,h("div",{class:"utext"},entry.text))));
        else{
          const turn=h("div",{class:"turn"},label,md(entry.text,"agent"));
          if(entry.evidence?.length)turn.append(h("div",{class:"tmeta"},entry.evidence.join(" · ")));
          if(entry.worker_id)turn.append(h("a",{class:"tmeta",href:nativeLink(entry.worker_id),on:{click:closeWarRoom}},"Full report / server sessions"));
          view.chat.append(turn);
        }
      }
      if(room?.inflight_job){const source=room.phase>0&&room.phase<=room.participants.length?room.participants[room.phase-1]:room.lead;view.chat.append(h("div",{class:"working"},h("span",{class:"cursor"}),`${source.role||"Investigator"} · ${name(source.server_id)} is reviewing evidence…`,h("a",{href:nativeLink(source.server_id),on:{click:closeWarRoom}},"Session / Stop")));}
      if(atBottom)view.chat.scrollTop=view.chat.scrollHeight;
    }
    if(room){note(room.error||`${room.status} · round ${room.round}/3 · read-only`);view.scopeLabel.textContent=room.case?`${name(room.case.server_id)} · Case #${room.case.id}`:room.server_ids.map(name).join(" · ");}
    else {view.scopeLabel.textContent=context.case_id?`${name(context.server_id)} · Case #${context.case_id}`:context.server_id?name(context.server_id):"Fleet investigation";note(servers.some(eligible)?"enter to send · shift+enter newline":"Update a server for War room and enable its model in normal Settings.",!servers.some(eligible));}
    view.scope.title=view.scopeLabel.textContent;
    updateSend();
  }
  function updateSend(){if(!view)return;view.comp.send.disabled=busy||!view.comp.ta.value.trim()||(current()?.status==="ended")||(!current()&&!servers.some(s=>s.id===lead&&eligible(s)));}
  async function refresh(){
    clearTimeout(timer);const mine=++request,mounted=host;if(!mounted?.isConnected)return;
    try{const [fleet,list]=await Promise.all([api("GET","/api/fleet"),api("GET",`/api/warroom/conversations?${query()}`)]);
      if(mine!==request||host!==mounted)return;servers=fleet;rooms=list;
      if(!lead){lead=servers.find(s=>s.id===context.server_id&&eligible(s))?.id||servers.find(eligible)?.id||"";if(context.server_id&&servers.some(s=>s.id===context.server_id&&eligible(s)))selected.set(`${context.server_id}:responder`,{server_id:context.server_id,role:"responder"});}
      if(!draft&&!rooms.some(r=>r.id===roomID))roomID=rooms[0]?.id||"";
      paint(current());if(rooms.some(r=>r.status==="active"||r.inflight_job))timer=setTimeout(refresh,5000);
    }catch(e){if(host===mounted&&mine===request){note(e.message,true);timer=setTimeout(refresh,10000);}}
  }
  async function send(text){
    if(busy)return;busy=true;updateSend();const mounted=host,generation=epoch;
    try{
      const base="/api/warroom/conversations",body=roomID?{text}:{lead,participants:Array.from(selected.values()),case:context.case_id?{server_id:context.server_id,id:String(context.case_id)}:null,question:text};
      const room=await api("POST",roomID?`${base}/${enc(roomID)}`:base,body);if(host!==mounted||epoch!==generation)return;roomID=room.id;draft=false;view.comp.ta.value="";view.comp.ta.style.height="auto";S.drafts[view.draftKey]="";view.roster.open=false;await refresh();
    }catch(e){if(host===mounted&&epoch===generation)note(e.message,true);}finally{if(host===mounted&&epoch===generation){busy=false;updateSend();}}
  }
  async function action(value){if(!roomID||busy)return;const generation=epoch;busy=true;updateSend();try{await api("POST",`/api/warroom/conversations/${enc(roomID)}`,{action:value});if(generation===epoch)await refresh();}catch(e){if(generation===epoch)note(e.message,true);}finally{if(generation===epoch){busy=false;updateSend();}}}
  return {
    mount(target,initial={}){
      this.close();host=target;context=initial;lead="";selected=new Map();roomID="";draft=false;rooms=[];signature="";busy=false;
      const draftKey=`warroom:${context.server_id||"fleet"}:${context.case_id||"new"}`;
      const comp=composer({draftKey,onSend:send,label:"Message War room",placeholder:"Ask the agents about this investigation…",maxLength:2000,initialValue:initial.question||""});
      const scopeLabel=h("span",{class:"chip-l"},context.server_id?name(context.server_id):"Fleet investigation");
      const scope=h("span",{class:"chip"},scopeLabel);
      const history=h("select",{class:"sel","aria-label":"War room conversation",on:{change:()=>{roomID=history.value;draft=!roomID;signature="";refresh();}}});
      const chat=h("div",{class:"tp-chat wr-chat","aria-live":"polite","aria-label":"War room discussion"});
      const rosterBody=h("div",{class:"wr-roster-body"});const roster=h("details",{class:"wr-roster"},h("summary",null,ic("bot",12)," Agents"),rosterBody);
      const chips=h("div",{class:"wr-agent-chips"});
      const status=h("div",{class:"wr-status sys",role:"status",hidden:true});
      const pause=h("button",{class:"btn small",hidden:true,on:{click:()=>action(current()?.status==="paused"?"resume":"pause")}},"Pause");
      const end=h("button",{class:"btn small",hidden:true,title:"End after the dispatched turn; use its native session Stop to abort it.",on:{click:()=>action("end")}},"End");
      view={chat,comp,scope,scopeLabel,history,roster,rosterBody,chips,pause,end,draftKey,status};
      comp.setChip("War room");
      comp.ta.addEventListener("input",updateSend);
      clear(host).append(h("section",{class:"wr-native tp-main","aria-label":"War room investigation"},
        h("div",{class:"wr-context"},scope,h("div",{class:"sp"}),history,h("button",{class:"ibtn",title:"New investigation","aria-label":"New investigation",on:{click:()=>{roomID="";draft=true;signature="";refresh();}}},ic("plus",14)),pause,end),
        h("div",{class:"wr-people"},chips,roster),chat,status,comp.el));
      if(initial.question)comp.ta.value=initial.question;
      refresh();
    },
    prefill(text){if(view){view.comp.ta.value=text;updateSend();view.comp.ta.focus();}},
    close(){epoch++;request++;clearTimeout(timer);host=null;view=null;}
  };
})();

/* =============================================================================
 * VRA — Vehicle Rating & Assessment  ·  Module: ARCHITECTURE
 * =============================================================================
 * SCOPE
 *   Draws the vehicle E/E architecture in three paradigms and lets the user
 *   inspect each ECU.  Pure rendering + interaction; ALL data (ECU roster,
 *   domains, zones, paradigm captions and references) comes from VRA.config.
 *
 *       Distributed  →  Domain-centralised  →  Zonal (SDV)
 *       (yesterday)      (today)                (tomorrow)
 *
 * STANDARDS COMPLIANCE
 *   ISO/SAE 21434:2021     Clause 9 (concept phase) — the architecture is the
 *                           basis for identifying cybersecurity-relevant items.
 *   UN ECE R155            §7.2.2.3 — the architecture supports the vehicle
 *                           type description required for CSMS type approval;
 *                           the security view (HPC partitions, FFI boundary,
 *                           attack paths) directly maps to R155 Annex 5 threats.
 *   SOAFEE v1.0            the zonal paradigm's guiding principles.
 *
 * OBJECTIVE VISUAL CONVENTIONS (no decorative subjectivity)
 *   • Orthogonal harness routing (vertical backbone + horizontal stubs) —
 *     convention, replacing freehand diagonals.
 *   • Connection nodes carry the standards-based terminology: automotive
 *     "ETH SW" (Ethernet switch, SOAFEE zonal backbone) vs gateway "PORT"
 *     (domain-centralised); the bus view uses the classic stub-connector
 *     representation of a shared CAN bus.
 *   • The zonal position glyph (mini vehicle, quadrant filled) is DERIVED
 *     from the zone name (Front/Rear × Left/Right) — data, not decoration.
 *   • Group header tints come from config.domains colors; zones use one
 *     neutral steel tone (physical zones have no domain color).
 *
 * DATA MODEL (from config)
 *   • Roster reproduces "Table 2 — Component Vulnerability Assessment".
 *   • Distributed/Domain views group by functional domain; Zonal by physical zone.
 *   • The Central Gateway / HPC is infrastructure (drawn as the core), not an
 *     assessed roster ECU.
 *
 * PUBLIC API
 *   VRA.architecture.render(paradigm) → SVG string
 *   VRA.architecture.init()           → wire DOM controls (auto on load)
 * ========================================================================== */
(function () {
  "use strict";
  var VRA = (window.VRA = window.VRA || {});
  var C = function () { return VRA.config; };   // late-bound config
  var M = function () { return VRA.model; };

  /* ---- SVG primitives ---------------------------------------------------- */
  function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;");}
  function rect(x,y,w,h,o){o=o||{};return "<rect x='"+x+"' y='"+y+"' width='"+w+"' height='"+h+"' rx='"+(o.r||0)+"' fill='"+(o.fill||"none")+"'"+(o.fo!=null?" fill-opacity='"+o.fo+"'":"")+(o.stroke?" stroke='"+o.stroke+"' stroke-width='"+(o.sw||1)+"'":"")+(o.dash?" stroke-dasharray='"+o.dash+"'":"")+"/>";}
  function line(x1,y1,x2,y2,o){o=o||{};return "<line x1='"+x1+"' y1='"+y1+"' x2='"+x2+"' y2='"+y2+"' stroke='"+(o.stroke||"#c9d2dc")+"' stroke-width='"+(o.sw||1.4)+"'"+(o.dash?" stroke-dasharray='"+o.dash+"'":"")+(o.marker?" marker-end='url(#"+o.marker+")'":"")+"/>";}
  function circle(cx,cy,r,fill){return "<circle cx='"+cx+"' cy='"+cy+"' r='"+r+"' fill='"+fill+"'/>";}
  function text(x,y,s,o){o=o||{};return "<text x='"+x+"' y='"+y+"' font-family='ui-monospace,Menlo,Consolas,monospace' font-size='"+(o.size||11)+"' fill='"+(o.fill||"#5a6472")+"'"+(o.anchor?" text-anchor='"+o.anchor+"'":"")+(o.weight?" font-weight='"+o.weight+"'":"")+">"+esc(s)+"</text>";}

  /** Mini vehicle top-view with the quadrant of `zoneKey` filled (derived). */
  function zoneGlyph(x,y,zoneKey,color){
    var front=/Front/.test(zoneKey), left=/Left/.test(zoneKey);
    var w=24,h=14,qw=(w-4)/2,qh=(h-4)/2;
    var qx=x+2+(front?0:qw), qy=y+2+(left?0:qh);   // front = towards the left edge
    return rect(x,y,w,h,{r:4,fill:"#fff",stroke:"#8a95a1",sw:1})+
           rect(qx,qy,qw,qh,{r:2,fill:color})+
           line(x-3,y+3,x-3,y+h-3,{stroke:"#8a95a1",sw:1.6});   // headlight bar = front
  }

  /** Connection node: Ethernet switch (zonal) or gateway port (domain). */
  function connNode(cx,cy,kind){
    var w=36,h=20,x=cx-w/2,y=cy-h/2,out="";
    out+=rect(x,y,w,h,{r:4,fill:"#fff",stroke:"#8a95a1",sw:1.3});
    out+=text(cx,cy+1.5,kind==="switch"?"ETH SW":"PORT",{anchor:"middle",fill:"#5d6672",size:6.8,weight:700});
    for(var i=0;i<4;i++) out+=rect(x+6+i*7,y+h-4.5,4,3,{fill:"#aeb8c2"});   // port ticks
    return out;
  }

  /* ---- layout constants -------------------------------------------------- */
  var L = { W:1040, extX:24, extW:156, coreX:336, coreW:150, grpX:606, grpW:410, top:30, headH:26, rowH:23, gap:16, pad:10 };

  /**
   * Group the roster for a paradigm: by physical zone (zonal) or functional
   * domain (distributed/domain). Controllers are listed first for readability.
   */
  function buildGroups(grouping){
    var cfg=C(), groups=[];
    var keys = grouping==="zone" ? cfg.zones : cfg.domains.map(function(d){return d.id;});
    keys.forEach(function(key){
      var members=cfg.ecus.filter(function(e){return (grouping==="zone"?e.zone:e.domain)===key;});
      if(members.length){
        members.sort(function(a,b){return (b.controller?1:0)-(a.controller?1:0);});
        groups.push({key:key,members:members});
      }
    });
    return groups;
  }

  /* Flat/distributed layout: ECUs hang directly off the shared bus with no
   * functional-domain grouping, but arranged by PHYSICAL zone for a car-like
   * picture — left column = Front-Left over Rear-Left, right column =
   * Front-Right over Rear-Right, each ECU stubbed straight to the central bus. */
  function renderFlat(cfg,P){
    var cols=[["Front-Left","Rear-Left"],["Front-Right","Rear-Right"]];
    var byZone={}; cfg.zones.forEach(function(z){byZone[z]=[];});
    cfg.ecus.forEach(function(e){ if(!byZone[e.zone])byZone[e.zone]=[]; byZone[e.zone].push(e); });
    var rowH=40, boxW=176, boxH=25, cx=L.grpX+54, gap=46, labelH=20, zoneGap=18;
    function colUnits(col){var n=0;col.forEach(function(z){if(byZone[z]&&byZone[z].length)n+=labelH+byZone[z].length*rowH+zoneGap;});return n;}
    var contentH=Math.max(colUnits(cols[0]),colUnits(cols[1]));
    var H=720, startY=Math.max(L.top+18,(H-contentH)/2);
    var svg="<defs><marker id='arr' markerWidth='7' markerHeight='7' refX='5' refY='3' orient='auto'><path d='M0,0 L6,3 L0,6 z' fill='#c0392b'/></marker></defs>";
    svg+=line(cx,L.top,cx,H-16,{stroke:"#c0392b",sw:4});
    svg+=text(cx,L.top-10,"Shared bus, flat, no trust boundary",{anchor:"middle",fill:"#c0392b",weight:700,size:10});
    // DISTRIBUTED era predates connectivity: the only entry is a PHYSICAL
    // connector (at best the OBD port) — no remote / V2X attack surface. The
    // attack path is a single straight line into the flat bus.
    var iface=cfg.interfaces, obdCy=L.top+42;
    svg+=text(L.extX+L.extW/2,obdCy-30,"no remote surface (pre-V2X)",{anchor:"middle",fill:"#8a95a1",size:8,weight:700});
    svg+=rect(L.extX,obdCy-15,L.extW,30,{r:6,fill:"#8a6d3b"});
    svg+=text(L.extX+L.extW/2,obdCy-2,iface[1].label,{anchor:"middle",fill:"#fff",weight:700,size:9.5});
    svg+=text(L.extX+L.extW/2,obdCy+11,"physical / OBD only",{anchor:"middle",fill:"#e8dcc4",size:8});
    svg+=line(L.extX+L.extW,obdCy,cx,obdCy,{stroke:"#c0392b",sw:2.2,marker:"arr"});
    svg+=text((L.extX+L.extW+cx)/2,obdCy-6,"physical (OBD) attack path",{anchor:"middle",fill:"#c0392b",size:7.5,weight:700});
    cols.forEach(function(col,ci){
      var onLeft=ci===0, x=onLeft?cx-gap-boxW:cx+gap, y=startY;
      col.forEach(function(zone){
        var members=byZone[zone]||[]; if(!members.length) return;
        svg+=text(onLeft?x+boxW:x,y+9,zone,{anchor:onLeft?"end":"start",fill:"#8a95a1",size:8.5,weight:700});
        y+=labelH;
        members.forEach(function(e){
          var by=y, cy=by+boxH/2, stubFrom=onLeft?x+boxW:x;
          svg+=circle(cx,cy,3,"#c0392b");
          svg+=line(cx,cy,stubFrom,cy,{stroke:"#aeb8c2",sw:1.4});
          var dot=M().color(e.domain);
          svg+="<g class='ecu' data-id='"+e.id+"' tabindex='0' role='button' aria-label='"+esc(e.name)+"'>";
          svg+=rect(x,by,boxW,boxH,{r:4,fill:"#fff",stroke:"#d3d9e0",sw:1});
          svg+=circle(x+12,cy,4,dot);
          var nm=e.name.length>22?e.name.slice(0,21)+"\u2026":e.name;
          svg+=text(x+21,cy+3.5,nm,{fill:"#26303b",size:9,weight:500});
          if(e.kind==="real") svg+=text(x+boxW-7,cy+3.5,"\u25C9",{anchor:"end",fill:"#84271c",size:8.5});
          svg+="</g>";
          y+=rowH;
        });
        y+=zoneGap;
      });
    });
    return "<svg viewBox='0 0 "+L.W+" "+H+"' width='100%' style='height:auto;display:block' role='img' aria-label='"+esc(P.label+" architecture diagram")+"'><rect width='"+L.W+"' height='"+H+"' fill='#f7f9fa'/>"+svg+"</svg>";
  }

  /**
   * Render the SVG for a paradigm.
   * @param {"distributed"|"domain"|"zonal"} paradigm
   * @returns {string} SVG markup
   */
  function render(paradigm){
    var cfg=C(), P=cfg.paradigms[paradigm]||cfg.paradigms.domain;

    /* DISTRIBUTED (bus): the network is physically flat, so ECUs hang directly
     * off the shared bus with NO functional-domain grouping — any node has
     * line-of-sight to the whole vehicle. Rendered as a scatter on both sides
     * of the bus rather than domain boxes. */
    if(P.core==="bus") return renderFlat(cfg,P);

    var groups=buildGroups(P.grouping);

    // vertical layout of the group boxes
    var y=L.top, boxes=[];
    groups.forEach(function(g){var h=L.headH+g.members.length*L.rowH+L.pad;boxes.push({g:g,y:y,h:h});y+=h+L.gap;});
    var H=Math.max(y+10,720), midY=H/2, svg="";
    var coreCx=L.coreX+L.coreW/2;

    // arrowhead marker for the attack path
    svg+="<defs><marker id='arr' markerWidth='7' markerHeight='7' refX='5' refY='3' orient='auto'><path d='M0,0 L6,3 L0,6 z' fill='#c0392b'/></marker></defs>";

    /* --- CORE: flat bus | central gateway | HPC with safety/non-safety --- */
    var isHpc=P.core==="hpc", isBus=P.core==="bus";
    var startX;
    if(isBus){
      svg+=line(coreCx,L.top,coreCx,H-20,{stroke:"#c0392b",sw:4});
      svg+=text(coreCx,L.top-10,"Shared bus, flat, no trust boundary",{anchor:"middle",fill:"#c0392b",weight:700,size:10});
      startX=coreCx;
    } else if(isHpc){
      // SECURITY VIEW: the shared HPC hosts mixed-criticality workloads, split into
      // NON-SAFETY (QM) and SAFETY-CRITICAL (ASIL) partitions separated by a Freedom
      // From Interference (FFI) isolation boundary. The security concern of the
      // shared architecture is that a non-safety compromise must not cross FFI.
      var hpcH=Math.min(H-2*L.top,262), hpcTop=midY-hpcH/2, hpcBot=hpcTop+hpcH, hdr=26;
      var splitY=hpcTop+hdr+(hpcH-hdr)*0.5;
      svg+=rect(L.coreX,hpcTop,L.coreW,hpcH,{r:11,fill:"#12161c"});
      svg+=text(coreCx,hpcTop+18,"HPC \u00B7 SOAFEE",{anchor:"middle",fill:"#fff",weight:700,size:12.5});
      var nsTop=hpcTop+hdr+3, nsBot=splitY-5, nsCy=(nsTop+nsBot)/2;
      var scTop=splitY+5, scBot=hpcBot-10, scCy=(scTop+scBot)/2;
      svg+=rect(L.coreX+9,nsTop,L.coreW-18,nsBot-nsTop,{r:6,fill:"#33271b",stroke:"#b45309",sw:1.3});
      svg+=text(coreCx,nsCy-3,"Non-safety",{anchor:"middle",fill:"#f4d9b8",weight:700,size:10.5});
      svg+=text(coreCx,nsCy+10,"QM workloads",{anchor:"middle",fill:"#c9a58a",size:8.5});
      svg+=rect(L.coreX+9,scTop,L.coreW-18,scBot-scTop,{r:6,fill:"#10281f",stroke:"#2f8f6e",sw:1.3});
      svg+=text(coreCx,scCy-3,"Safety-critical",{anchor:"middle",fill:"#bfe6d6",weight:700,size:10.5});
      svg+=text(coreCx,scCy+10,"ASIL workloads",{anchor:"middle",fill:"#8fc7b0",size:8.5});
      svg+=line(L.coreX+7,splitY,L.coreX+L.coreW-7,splitY,{stroke:"#e0b64a",sw:2,dash:"5 3"});
      svg+=rect(coreCx-52,splitY-7,104,14,{r:3,fill:"#12161c"});
      svg+=text(coreCx,splitY+3,"\u2016 FFI isolation \u2016",{anchor:"middle",fill:"#e0b64a",size:8.5,weight:700});
      svg+=text(coreCx,hpcBot+14,"shared compute, one trust boundary",{anchor:"middle",fill:"#84271c",size:8.5,weight:700});
      startX=L.coreX+L.coreW;
    } else {
      svg+=rect(L.coreX,midY-32,L.coreW,64,{r:7,fill:"#12161c"});
      svg+=text(coreCx,midY-8,"Central",{anchor:"middle",fill:"#fff",weight:700,size:11.5});
      svg+=text(coreCx,midY+9,"Gateway",{anchor:"middle",fill:"#fff",weight:700,size:11.5});
      svg+=text(coreCx,midY+25,"domain trust boundary",{anchor:"middle",fill:"#93a2b3",size:9});
      startX=L.coreX+L.coreW;
    }

    /* --- external attack surfaces; remote routes into the non-safety side --- */
    var iface=cfg.interfaces, coreLeft=isBus?coreCx:L.coreX;
    svg+=rect(L.extX,midY-46,L.extW,36,{r:6,fill:"#b45309"});
    svg+=text(L.extX+L.extW/2,midY-30,iface[0].label,{anchor:"middle",fill:"#fff",weight:700,size:9.5});
    svg+=text(L.extX+L.extW/2,midY-18,"remote attack surface",{anchor:"middle",fill:"#f4d9b8",size:8});
    svg+=rect(L.extX,midY+12,L.extW,32,{r:6,fill:"#8a6d3b"});
    svg+=text(L.extX+L.extW/2,midY+31,iface[1].label+", local",{anchor:"middle",fill:"#fff",weight:700,size:9.5});
    svg+=line(L.extX+L.extW,midY-28,coreLeft,midY-28,{stroke:"#c0392b",sw:2,marker:"arr",dash:"5 3"});
    svg+=text((L.extX+L.extW+coreLeft)/2,midY-34,"remote attack path",{anchor:"middle",fill:"#c0392b",size:7.5,weight:700});
    svg+=line(L.extX+L.extW,midY+28,coreLeft,midY+28,{stroke:"#c0392b",sw:2.2,marker:"arr"});
    svg+=text((L.extX+L.extW+coreLeft)/2,midY+22,"physical (OBD) attack path",{anchor:"middle",fill:"#c0392b",size:7.5,weight:700});

    /* --- harness: vertical Ethernet backbone spine + HPC port --------------- */
    if(!isBus && boxes.length){
      var tx=startX+28;
      var topMid=boxes[0].y+boxes[0].h/2, botMid=boxes[boxes.length-1].y+boxes[boxes.length-1].h/2;
      var spineTop=Math.min(topMid,midY), spineBot=Math.max(botMid,midY);
      svg+=line(startX,midY,tx,midY,{stroke:"#aeb8c2",sw:2.4});          // HPC → spine
      svg+=circle(startX,midY,3,"#8a95a1");                             // port at core edge
      svg+=line(tx,spineTop,tx,spineBot,{stroke:"#aeb8c2",sw:2.4});     // vertical backbone
      svg+=text(tx+8,spineTop-8,isHpc?"automotive Ethernet backbone":"gateway links",{fill:"#8a95a1",size:7.5,weight:700});
    }

    /* --- group boxes + connection nodes + ECU rows --- */
    boxes.forEach(function(b){
      var boxMidY=b.y+b.h/2;
      if(isBus){
        // classic shared-bus stub connector: junction dot on the bus + stub line
        svg+=circle(coreCx,boxMidY,3.4,"#c0392b");
        svg+=line(coreCx,boxMidY,L.grpX,boxMidY,{stroke:"#aeb8c2",sw:1.6});
      } else {
        var spineX=startX+28, swX=L.grpX-44;          // switch sits at the zone entry
        svg+=circle(spineX,boxMidY,2.6,"#aeb8c2");     // junction on the backbone
        svg+=line(spineX,boxMidY,swX-18,boxMidY,{stroke:"#aeb8c2",sw:1.6});  // backbone → switch
        svg+=connNode(swX,boxMidY,isHpc?"switch":"port");
        svg+=line(swX+18,boxMidY,L.grpX,boxMidY,{stroke:"#aeb8c2",sw:1.6});  // switch → box
      }
      var groupColor=P.grouping==="zone"?"#2c3743":M().color(b.g.key);
      svg+=rect(L.grpX,b.y,L.grpW,b.h,{r:8,fill:"#fff",stroke:"#d3d9e0",sw:1});
      svg+=rect(L.grpX,b.y,L.grpW,L.headH,{r:8,fill:groupColor,fo:0.09});
      svg+=rect(L.grpX,b.y,4,b.h,{fill:groupColor});
      var title=P.grouping==="zone"?b.g.key+" zone":b.g.key;
      svg+=text(L.grpX+16,b.y+17,title,{fill:"#101720",weight:700,size:11.5});
      if(P.grouping==="zone") svg+=zoneGlyph(L.grpX+L.grpW-108,b.y+6,b.g.key,groupColor);
      svg+=text(L.grpX+L.grpW-12,b.y+17,b.g.members.length+(b.g.members.length===1?" ECU":" ECUs"),{anchor:"end",fill:"#98a2ad",size:9.5});

      b.g.members.forEach(function(e,i){
        var ry=b.y+L.headH+i*L.rowH, cy=ry+L.rowH/2, dot=M().color(e.domain);
        svg+="<g class='ecu' data-id='"+e.id+"' tabindex='0' role='button' aria-label='"+esc(e.name)+"'>";
        svg+=rect(L.grpX+8,ry+2,L.grpW-16,L.rowH-3,{r:3,fill:i%2?"#f6f9fa":"#ffffff"});
        svg+=circle(L.grpX+20,cy,4.5,dot);
        svg+=text(L.grpX+32,cy+3.5,e.name,{fill:"#26303b",size:10.5,weight:500});
        // right-aligned tags: real (anonymised) is highlighted; ctrl / ext markers
        var tags="";
        if(e.kind==="real") tags+="<tspan fill='#84271c' font-weight='700'>\u25C9 real</tspan>  ";
        if(e.controller)    tags+="<tspan fill='#0b6b74'>\u25C6 ctrl</tspan>  ";
        if(e.external)      tags+="<tspan fill='#b45309'>\u25B2 ext</tspan>";
        if(tags) svg+="<text x='"+(L.grpX+L.grpW-12)+"' y='"+(cy+3.5)+"' text-anchor='end' font-family='ui-monospace,monospace' font-size='9'>"+tags+"</text>";
        svg+="</g>";
      });
    });

    return "<svg viewBox='0 0 "+L.W+" "+H+"' width='100%' style='height:auto;display:block' role='img' aria-label='"+esc(P.label+" architecture diagram")+"'><rect width='"+L.W+"' height='"+H+"' fill='#f7f9fa'/>"+svg+"</svg>";
  }

  /* ---- interaction: detail panel (kind + Table 2 ref for audit) ---------- */
  function showDetail(id){
    var host=document.getElementById("arch-detail");
    if(!host) return;
    var e=id&&M().ecu(id);
    if(!e){host.innerHTML="<span class='muted'>Select a component to inspect it. The last selection remains displayed.</span>";return;}
    var c=M().color(e.domain);
    var kindLabel=e.kind==="real"?"real (anonymised)":"simulated";
    host.innerHTML="<span class='dot' style='background:"+c+"'></span><b>"+esc(e.name)+"</b>"+
      "<span class='meta'>Domain <b style='color:"+c+"'>"+e.domain+"</b> · Zone <b>"+e.zone+"</b>"+
      (e.controller?" · <b style='color:#0b6b74'>domain controller</b>":"")+
      (e.external?" · <b style='color:#b45309'>external-facing</b>":"")+
      " · Source <b>"+kindLabel+"</b> · Table 2 ref <b class='mono'>"+esc(e.ref||"—")+"</b></span>"+
      "<span class='note'>"+esc(e.note||"")+"</span>";
  }
  /* Sticky selection: a click (or keyboard Enter/Space) selects a component and
   * KEEPS it shown until another is picked — easier to read than hover. */
  function wireDiagram(){
    var host=document.getElementById("arch-diagram");
    if(!host) return;
    host.querySelectorAll(".ecu").forEach(function(g){
      var id=g.getAttribute("data-id");
      function select(){
        host.querySelectorAll(".ecu.sel").forEach(function(p){p.classList.remove("sel");});
        g.classList.add("sel");
        showDetail(id);
      }
      g.addEventListener("click",select);
      g.addEventListener("keydown",function(ev){ if(ev.key==="Enter"||ev.key===" "){ev.preventDefault();select();} });
    });
  }

  /* ---- legend ------------------------------------------------------------ */
  function renderLegend(){
    var host=document.getElementById("arch-legend");
    if(!host) return;
    var sw=C().domains.map(function(d){return "<span class='lg'><i class='sw' style='background:"+d.color+"'></i>"+d.label+"</span>";}).join("");
    host.innerHTML=sw+
      "<span class='lg'><i class='mk' style='color:#84271c'>\u25C9</i>real (anonymised)</span>"+
      "<span class='lg'><i class='mk'>\u25C6</i>domain controller</span>"+
      "<span class='lg'><i class='mk' style='color:#b45309'>\u25B2</i>external-facing</span>"+
      "<span class='lg'><i class='sw' style='background:#33271b;border:1px solid #b45309'></i>HPC non-safety (QM)</span>"+
      "<span class='lg'><i class='sw' style='background:#10281f;border:1px solid #2f8f6e'></i>HPC safety (ASIL)</span>"+
      "<span class='lg'><i class='mk' style='color:#e0b64a'>\u2016</i>FFI isolation boundary</span>"+
      "<span class='lg'><i class='sw' style='background:#fff;border:1px solid #8a95a1'></i>Ethernet switch / gateway port</span>"+
      "<span class='lg'><i class='sw' style='background:#fff;border:1px solid #8a95a1'></i>zone position glyph (from zone name)</span>"+
      "<span class='lg'><i class='mk' style='color:#c0392b'>\u2192</i>external attack path</span>";
  }

  /* ---- caption: description + source reference + SOAFEE principles -------- */
  function paint(paradigm){
    var cfg=C(), P=cfg.paradigms[paradigm]||cfg.paradigms.domain;
    var d=document.getElementById("arch-diagram");
    if(d) d.innerHTML=render(paradigm);
    var cap=document.getElementById("arch-caption");
    if(cap){
      var html="<b>"+P.era+" · "+P.label+".</b> "+P.caption;
      if(P.reference){
        var r=P.reference, cite=r.url?("<a href='"+r.url+"' target='_blank' rel='noopener'>"+esc(r.cite)+"</a>"):esc(r.cite);
        html+="<div class='cap-ref'>Reference: "+cite+(r.note?" <span class='muted'>("+esc(r.note)+")</span>":"")+"</div>";
      }
      if(P.principles && P.principles.length){
        html+="<ul class='cap-princ'>"+P.principles.map(function(p){return "<li>"+esc(p)+"</li>";}).join("")+"</ul>";
      }
      cap.innerHTML=html;
    }
    wireDiagram(); showDetail(null);
  }

  /* ---- init -------------------------------------------------------------- */
  VRA.architecture={
    render:render,
    init:function(){
      if(!VRA.config){return;}
      renderLegend();
      var sel=document.getElementById("arch-select");
      paint((sel&&sel.value)||"domain");
      if(sel) sel.addEventListener("change",function(){paint(this.value);});
    }
  };
  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded",VRA.architecture.init);
  else VRA.architecture.init();
})();

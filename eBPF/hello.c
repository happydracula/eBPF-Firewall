#include "packet.h"
#include <linux/ipv6.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, long);
        __uint(max_entries, 4);
} packetmap SEC(".maps");
 int start=0;
static long w[]={-69479594230,11901599168,2500199079,-2607380449,-24641530513,13383374214,-69166355133,-58679885864,3779276907,-52503585815,-71488184928,-45698680877,-22632234096,-10136816501,10018008947,-17564778327,-39342002868,-69312715530,-8306067585,-71114850044,-1575125157,-70886273384,-58114438056,3957119584,71789813,-70845594406,-52574253082,6550760865,-69804992675,-69440197944,-72024855613,3828105628,-39779863357,-69727072715,10264942646,7073885798,8304674625,8264062404,1540573090,158952008,-20541558265,6059666872,5576000809,22740669250,-13243985176,17048531770,9042693376,10715656280,-73138136863,10322566032,-2119734883,5191056728,-3921920955,-69654836654,-116756577,-68708882331,-70372471809,-31716823577,7855271100,16705645322,5176187157,8515692353,403546392,-5040612220,1484769880,2812910676,-1840742677,-4740015566,-1297629028,-5858247876,-8507584333,-4661387205,-4135620594,-5539399981,-4624689221,-4289668798,-7371320128,4189730882,1393538415,3324387371,2272336333,5080407261,4864163994,-1150259822,-1651887446,3818111717,-5116910338,5299833416,-971532464,6176469922,-9043041467,7743985056,2494026571,1601756215,5342616438,9009886384,-4658906757,-9059950113,-7849211096,-11870708465,-22032928466,8631418943,-3477517068,21469016075,8759702444,-8070484995,8795205354,4454885423,5701809525,4938730299,9295284748,10271338224,8481403589,14181199073,14816002845,8934052586,8719761967,20749249458,10100014209,8011765480,7243000268,12591675519,11825737953,10075144767,11849212646,8458055257,-25122601985,-70514140129,-3091455698,-4006730020,-16339943408,-16557633876,-15209984779,-20670642852,-1882803440,-14038478136,-11935290098,-5068497061,2365332990,4860203266,-10890129804,-5916384458,-5670879483,3323686718,-5204235315,-23626174926,2781874835,-6285645365,-16166274547,-6934124827,-2974750995,-2278524190,59409961,-5213590264,2802985608,-18578360080,-6770570278,585846938,-10495038032,6359825134,-12525522708,-5425887703,10401616096,-8614017963,-3914762735,5139803886,-7334838509,5209535956,-3716983199,-19872684478,2993082106,1752238273,495683625,3750124871,-7135880589,11264489889,6492826342,9422720670,11491129398,4576753079,8518314361,14783183336,11140024662,7547726035,-8641650080,17509051561,7692161202,5660210847,9196888804,5365000367,11555613279,2976113557,9630802869,3836495578,4053246676,3176200687,2809446454,12358070611,5675143599,-6558293104,4133567810,5132473707,6436126232,4316247105,-12582820653,-5683246850,-4819215834,-7525464892,-10463652610,-2565922439,-1167243942,4084259271,-354676581,1716257929,-71709985733,-73643269538,5368949174,-2294585704,6424652934,-2433593124,9109290838,4717068374,9360761642,10250326395,-69269981384,-69464912414,-72609028816,-70660810470,-71432099342,-72823500633,-68983507156,-71334943771,-71864986419,-71232643127,-70201625823,-69714331626,-69960112571,-72210435867,-71072554588,-72455964088,-68249411582,-70670771598,-72400798797,-71202907562,-66633219718,-67391667366,-71314487457,-68984155654,-71721529960,-69171586036,-70107154846,-69733867645,-71808834075,-72774157524,-70369868278,-72348327636,2628349065,-6299491524,-4928786754,-5003347396,-5082506537,-2646787166,-682336539,-2051050364,-295633468,-3575707972,-2890506982,-5266060233,-2215154320,-818486586,-2168200165,-294316466,-4048689305,873805806,-6180471181,-5376242399,-571249164,-6453260183,2497963011,-2617816329,-1731684505,-1415634453,-328663624,-3622207641,-1562027782,-2330853492,-5877751708,-4193658232,5272431373,-2061831355,1763515025,3779848515,945703387,-3105078935,-1094484254,-2613556981,-3891577124,-2342374473,2621945738,1536228805,813055634,-1935873627,-4044191539,-104951951,-605624839,1187520772,-5339026451,-3414157927,-3865418136,-994778648,-2648175656,-2515771389,1452413946,869291722,-1871071606,5627183318,-8325484395,-2872113287,11237785816,-4591768383,526816323,1902793645,-2905389368,-2666642665,2701825201,-1851891875,5537654161,933924838,2044545263,-2050991356,-115173170,1848052740,-2024611383,-4472672343,1325331032,-3348980545,-3399928510,-2519681751,587966851,-1702721,-4120915532,-2299782186,-2569113969,-1603584736,-105736115,4804275035,3271072208,2024400532,5493831634,3243344426,2609894573,593134872,-1382581591,-386384949,-1198161840,2091665267,-3953237831,3018901944,626758486,-5419065356,-2433165907,3239381015,419883467,1424942463,-2413820475,2502516508,1835477650,-4676881432,-4996292293,-3319778144,-3107581436,-5163844823,507703460,922765508,-3502708077,3432606458,-3880340456,-6713463068,-1366864293,-4980103969,-2067141085,-2295268326,759240612,-3174953758,1415520757,81394035,-2348306328,-3473999798,-786836221,-907396227,-489743128,-1993503570,-150827830,790010765,207934416,-1493828743,-2346561402,2335958182,-132298767,1194778531,-2965366840,-4656277298,-4054811894,-4140756130,-2539492845,-6765451431,-3894893527,4496017396,3298022747,-55521042,2329203635,-2083858698,839176923,240481160,1552197188,-1599878966,-945062860,-1420716047,-3133681118,-2330715209,-2788815200,-889794528,549500919,5743131637,-781285539,-4158375859,4153516590,-5491589307,2649979591,-1607934236,-2460175454,1986237466,-1995441019,-3251410126,2949851453,-3286263644,3845696449,-1238152235,6741768717,3699602782,6019421815,5738747715,-1030254811,2456263750,16018855571,5648803710,621367506,-725118815,-1010682284,-3681095838,-2245786935,-1077543124,-3381579816,844280868,836187750,9534634947,-236977785,-1859472244,-2712222337,2335488349,1247693747,910375639,-2869655489,-3800493180,-1800776869,1252860426,6730528473,-595279186,37441249,-4012776017,-2047880738,-3690405488,1187173798,-3473080694,-3646366298,2738281488,1180325895,1185648441,3395164608,1205491200,-1116796806,-826974809,2293407171,5595171451,1499902456,-963193699,2798463702,-2451851516,4738399982,930011942,7566636204,4978287518,5413806438,-1307114511,-474915578,2400550544,-1720989942,9580186009,-860163047,3259050548,-421781204,3730594813,-2527753710,1248053237,3318577408,3287305533,-624501183,2340939193,-3718699216,-3760506510,-1632997989,6095449328,2431315630,2644984722,-86917951,-654165670,-1557805091,2021566927,-2084332555,-1930761188,612567663,-1063326299,461222901,1077451556,-518475510,-663618370,-1045371145,-1078541874,308850370,1239884868,-332827493,-102761089,1836925595,-1361546069,-2077601552,-809527114,3936831951,481672473,1304997950,-1357825845,-2340295612,-1355203092,-832333713,4551811218,1109489053,239672772,-72023058,-2522607743,-186191331,-1147260665,-545783601,-1805218607,2402286678,-321674831,743608027,-468087978,-335861109,-567861720,1509600579,940037891,-187854003,313874073,670858100,1527961045,-402199700,-1500996351,-1101096868,2642575502,2083541154,416583865,-87465327,-154911633,118307415,812819525,865778774,-1018992885,1484543532,-894160121,-137962307,976753681,142123512,892753601,1184270977,319228619,170321818,-812432244,1385855376,-228998586,-297582224,-747222900,-210431758,558118782,1385428309,-1186145022,893132761,-1537462323,2679514586,-909210443,111268144,-2181039899,943044796,-512649230,-743639618,425671301,-38415300,1259323209,-525954291,-921156108,-392396301,687783882,62298704,-1039978191,-234307162,1500388234,2128252834,2266372293,168747361,-54672448,1855566352,-2926856279,-1995436251,-593171827,-1763386875,-1868675202,-726967081,672183036,-234100259,-581601783,2816171050,-623232610,243677981,-942656025,-18073875,-816219523,113884601,-96645457,-1448093056,555531010,-2454675137,-2093929052,977353155,-121453143,864543989,-1135835647,50374874,933770239,316197089,1514505594,-842512771,1254292279,3961794376,-1499074846,-923508852,-337519422,-2688009142,145293902,802229642,2890233695,-16890560,512699075,-833239853,283066295,-110150137,-450901612,-1569435745,-1149255931,-891858935,-2091425061,914450809,-925091207,49854470,-1685562580,-1429581344,538617260,-417961664,141311446,-1428768783,-1686176955,-1339322328,-1264597624,143978968,-1215580403,-1624909639,-2146544307,1556873619,-1216772124,-1760324537,-220205467,6940325498,2439070940,34565285,-941981375,261988062,-381262898,-402440614,-1946803927,909032151,-689048469,-1455510109,-579479523,-1351882815,-2239626497,-286067649,-1762326210,189943872,-677392631,487947799,-395776666,214030463,4505205750,313471630,-1782534718,-1023473367,447455644,-1679927706,1877405196,310307797,-143058877,146650876,-2461804449,804691240,-1059433892,991181060,1306632161,890945494,-838330239,801805555,371044054,-1400017738,-1118234321,-348239019,-1047948673,-1070764735,-1543094515,-1968112587,-2526815831,314657799,393710136,1844955682,900377705,1699454486,-747711732,2939669787,-1695718467,1285223364,1874293833,-2428455799,-1340454965,1226461529,-1686666756,1408960074,-2822014093,3198274374,-1689762473,-3222781717,-1627607047,-261523015,264445953,-1497509181,1044419854,2951969802,1331413388,-2058883458,51558907,706575959,-733711645,-1258941739,-1950891166};
SEC("xdp")
int hello(struct xdp_md *ctx) {
	__u32 key;long* value;
if(start==0){
	key=2;
	value = bpf_map_lookup_elem(&packetmap, &key);         
 	if (value)    *value= bpf_ktime_get_ns();
	start=1;	
}
key=3;
value = bpf_map_lookup_elem(&packetmap, &key);
if (value)    *value=bpf_ktime_get_ns();
struct iphdr*iph=retrieve_ip(ctx);
unsigned int source=lookup_source(iph);
if(source==0x0101a8c0){
             key=0;
	bpf_printk("Dropped packet from source:%pI4",&source);
	 value = bpf_map_lookup_elem(&packetmap, &key);
                if (value)
                        *value += 1;
	return XDP_DROP;
}
else{
        long drop=b;
		for (int i = 0; i < 3; i++) {
  	      int k=256 * i + ((source >> (8 * i)) & 0xFF);
	      drop+=w[k];
 }
	if(drop==1){
		key=0;
	 value = bpf_map_lookup_elem(&packetmap, &key);
                if (value)
                        *value += 1;
		bpf_printk("Dropped malicious packet from source:%pI4",&source);
		return XDP_DROP;
         } 
	bpf_printk("Passed packet from source:%pI4",&source);
	key=1;
	 value = bpf_map_lookup_elem(&packetmap, &key);
                if (value)
                        *value += 1;
        return XDP_PASS;
}
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";

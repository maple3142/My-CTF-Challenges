# Three Pieces

* Round: 42 (2024/01~2024/02 mid)
* Category: Crypto
* Points: 100
* Solves: 5

## Description

Yet another completely unrealistic RSA challenge.

## Solution

Use resultants to find a multiple of p, then gcd to factor n.

```python
from Crypto.Util.number import *

n = 18151436781040535621934494314823541571425378331588402644471998994607233932578523603309906936111527958944993223437469803645501458952977318870116001247472152973076841975875195787195427229913632873233466150296819954192237327011380701539033389941418863333194165249630183168596947990083896900054143914273835596929016022671643256571480139608656638131256826992541764075868492778252607295415448491505592201910696274547745074072625294489478684913950233100467300743625131497788070241995158236798857776127377475397143406431995355060379875866331463124957719958974264347599826499720330673194456875804125482418777387080825072808477
c = 5597529447317281845732150143481384990515257475065984937867929885590236305761542308404378842327946625154567873935675088135140334771018320908295722027162617290258014488996389902673165081616512829888166249175391634549928277390636906611949785661222177820358688251877720280350026843998219210217957127102576556873995113018230179725966658532121149882331305111934622638347171921657890122964488344961812861798354066739811447049248103699371315425933629081309716676905383199279565238822683366495315922830079699561586218085813287031169998600577311259564782948140351978342323229417553318749426925738515349495905985080192115642910
c1 = 7981952130586667763355256460807654345212067937297158985484430990536716447989998373542267535941671882470905661591597048075614184614509539728192893363098871686541987184579224056125774264340729112721466484126162190961859808411695969329499951026232964217260458539503445395975734335326028774517230187782388086115175614480634212751296194821337817371296013468124454338344523413573448593801089827034697466498516046053301136207156930681634090804259356825011336763857167267252173320025419297696130906691635246622267599007388604638107562483940536900681907195823435713147214746468782499774155467292932715985947336967984153951351
c2 = 15191767561454572805162058357116357363591652570875524740262169945482435873934091228044673308807538758676938534201246675879636301409749556073887177590667140986706239318944396785892597418337030319785181066886518858706635816925064731337525741194800948210770511204126270681914076435835620138215966334176162058949325854072562200415917652146200174081373048805198336669940170377657765795653774968403346246594855353178267062841850832768244853277282672610548594189501994699785376663753663367042700126415640031560423720974711862869296316396500862563855025750404243335095749658659834968795037595797842312901624804029835549246748
c3 = 17000042193113121702083810774599626655956628637807539852609283854387954407637509780538764580282929357808409050436800779371384105117258916426031109929680765865302096945275986528445332930670089429176426605991878962110096544586873393661589897149085683313297776791217984347754893374247674106304224583927536958980398641089805511532435792910430853633721695555047768679426794855871140700815744118807428103775217730784220387420927688403212138221079006822806209005257752247003351289162906107803595148025625185927015575662827595369165779020641629426870760900311225410968211223922331833195319894173486597169538739440767679968742
e = 23

PR = PolynomialRing(QQ, "x, y, z")
x, y, z = PR.gens()
f1 = x**e - c1
f2 = y**e - c2
f3 = z**e - c3
f4 = x + y + z
g = ZZ(f1.resultant(f4, x).resultant(f2, y).resultant(f3, z))
p = gcd(g, n)
q = n // p
phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag)
```
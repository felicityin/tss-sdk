package logproof

import (
	"fmt"
	"math/big"
	"testing"

	edwards "github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"

	"tss-sdk/tss/crypto"
	zKpaillier "tss-sdk/tss/crypto/alice/zkproof/paillier"
)

var (
	config   = crypto.NewProofConfig(edwards.Edwards().N)
	p0, _    = new(big.Int).SetString("104975615121222854384410219330480259027041155688835759631647658735069527864919393410352284436544267374160206678331198777612866309766581999589789442827625308608614590850591998897357449886061863686453412019330757447743487422636807387508460941025550338019105820406950462187693188000168607236389735877001362796259", 10)
	q0, _    = new(big.Int).SetString("102755306389915984635356782597494195047102560555160692696207839728487252530690043689166546890155633162017964085393843240989395317546293846694693801865924045225783240995686020308553449158438908412088178393717793204697268707791329981413862246773904710409946848630083569401668855899757371993960961231481357354607", 10)
	n0       = new(big.Int).Mul(p0, q0)
	n0Square = new(big.Int).Exp(n0, big2, nil)
	ssIDInfo = []byte("Mark HaHa")
	pedp, _  = new(big.Int).SetString("172321190316317406041983369591732729491350806968006943303929709788136215251460267633420533682689046013587054841341976463526601587002102302546652907431187846060997247514915888514444763709031278321293105031395914163838109362462240334430371455027991864100292721059079328191363601847674802011142994248364894749407", 10)
	pedq, _  = new(big.Int).SetString("133775161118873760646458598449594229708046435932335011961444226591456542241216521727451860331718305184791260558214309464515443345834395848652314690639803964821534655704923535199917670451716761498957904445631495169583566095296670783502280310288116580525460451464561679063318393570545894032154226243881186182059", 10)
	pedN     = new(big.Int).Mul(pedp, pedq)
	pedT     = big.NewInt(9)
	pedS     = big.NewInt(729)
	ped      = &zKpaillier.PederssenOpenParameter{
		N: pedN,
		S: pedS,
		T: pedT,
	}
)

func TestLogProof(test *testing.T) {
	x := big.NewInt(3)
	rho := big.NewInt(103)
	C := new(big.Int).Mul(new(big.Int).Exp(new(big.Int).Add(big1, n0), x, n0Square), new(big.Int).Exp(rho, n0, n0Square))
	C.Mod(C, n0Square)
	X := crypto.ScalarBaseMult(edwards.Edwards(), x)

	// ok
	zkproof, err := NewKnowExponentAndPaillierEncryption(config, ssIDInfo, x, rho, C, n0, ped, X, nil)
	assert.NoError(test, err)
	err = zkproof.Verify(config, ssIDInfo, C, n0, ped, X, nil)
	assert.NoError(test, err)

	// not in range
	config.TwoExpLAddepsilon = big.NewInt(-1)
	zkproof, err = NewKnowExponentAndPaillierEncryption(config, ssIDInfo, x, rho, C, n0, ped, X, nil)
	assert.Error(test, err)
	assert.Empty(test, zkproof)
}

func TestRealLogProof(test *testing.T) {
	ec := edwards.Edwards()
	proofParameter := crypto.NewProofConfig(ec.N)
	contextI := []byte{245, 179, 33, 71, 4, 237, 175, 194, 197, 194, 88, 106, 74, 171, 194, 239, 152, 246, 248, 35, 239, 229, 97, 145, 241, 137, 110, 236, 124, 25, 104, 62}
	kCiphertexts, _ := new(big.Int).SetString("287651608139423769879872373700768499702324647559053832364522545973449461059479117071311672049089107591313775696893110135468444958059713753541045481680317694143276407968490807738957332146723623649812981128690844536494004297486481616370408120679470136836380224727564486552062262694727231639466826662632504377310620427636160418454547438942874641660286987664332420847496047563813377579512400704548987218100546848757755445114072525396022748416489886024555839987432239035484045903354148882760240003287172944275838450207490674166823851872755243208302954903358626142276610641673366641239834535011452310207442316951361785950994660719513145532887302938810266070445503731705635826479963250583389555460154823806559350592526676320931630915055452136356344531647110502891775375887527688774195890487558029472772152233666988917571160221050811237237645323972775971359360246326465364434306841599840186342440970177433249680899409987930962021920222935823323125949318890486481357185943118186595605258647190101388041990492233672684534386308908776931154482018474418700225668162546067693187695969737071711437875886891770790332391963010105223144077473703044166798452423872070931532245862422458577543115782308413137264839464773872689213515620635074722842335222", 10)
	paillierPKN, _ := new(big.Int).SetString("27828372639832346189521536175977044007044506900345718337482096423623646125100786613684172916802252998074652914350932263377643965052216022768005192372271209281985994694476495085882449144088862226570465190557813309319533439774461100809607335249783889073821582681460274385494093848115541169842962884092203385551498743525962686289863674698641471232570438924161084594593671890167664158824707584836047250014838753005856496522431623259082870035627192897391845537555167593117127735930636842807707751418169977757348345824570471363723720148560546321010466508200162072145147023731918110012655998095386124565631539709226487684509", 10)

	N, _ := new(big.Int).SetString("24501403862518051129291459699541902903409434264351552893704719387285527682799106556348707170317509168639060164456738501088909418848924242633551337046444761472313533507997257792517904975221481658336024863308397976614898161134273450832912245586262017105045476394028503997923172676874683538165032638473452498236381451333365040831551742304641328589815951119721801927835546857761690744465682681880012859376513148992548741040341779027224005514824289930222939782151035069689984913390529127099821847277387807350033038998782937271370806782491491051004143567252884447948432705918522158199694041260836581121966380567128498189301", 10)
	S, _ := new(big.Int).SetString("4881230608897506997551552774105065633462043819497294944823921194775705872984493576016746799298813089894632185319098502621829260786414507657250063206972583165357648060622654563204168994144101445901684985033303519635369854907179010664306549613311364780444106770679245172473586740260422171171186583354906343034557284173659995645474655924589576262511984440549132895645213932880498532078725492382986323633666564215283656477199933029319863248184505591201197036496663387538297996701700985421391919096945783204685001058724739192324746095644539959411016232703354149633810534342507166750765801309929112745038909827825748771741", 10)
	T, _ := new(big.Int).SetString("3254643541145451823583579246773999442930729818569381023437174973246677851164517898858342146171202040587955167263412695086563346027031567651634530899282128236961340796707413108407808052417547811454589624923514809847366448274652131701562805317286460555515734686482632718190772215760308886852094800001135387198234547971427736711450288778790012106997196861104579729456888874846660302006054537931999931138795548626993750086373221585982914689177925994235212466932829592013194183472026690399404046773555291921757199152076571705897388845979317492594939041274999629612502869929528570251603477180619636238492436402293056116264", 10)
	ringPedersenPK := &zKpaillier.PederssenOpenParameter{
		N: N,
		S: S,
		T: T,
	}

	RiX, _ := new(big.Int).SetString("10572993586516734219551332451747528308801788412033618686576841475641596029568", 10)
	RiY, _ := new(big.Int).SetString("20876302078176891242215373638582567540160618843303179521783876273127701350698", 10)
	Ri, _ := crypto.NewECPoint(ec, RiX, RiY)

	k, _ := new(big.Int).SetString("6243111752332290845546866078309593702173971284255407247776457075243936826889", 10)
	rho, _ := new(big.Int).SetString("24741564452570157847189942837225208035340789428282032392587272419856592198318799117783589081456764937862907274933235265759095111456384206307117693758851740259631151798321009772732527058254816941187744514565139730546802630500504830029858387500068645472219957155555723716139725683268007835854336670721230246762062904068502560761479068688808555581832340307937161579433478277341594463609629055508898979162414952888624110953856968771528236414048978500353458815987520433486896073107461322288984506858676641526981087743660503899143801461559189029954102645546650031343297874911946374582543747471855291798065316388797194517433", 10)

	for i := 0; i < 200; i++ {
		zkproof, err := NewKnowExponentAndPaillierEncryption(proofParameter, contextI, k, rho, kCiphertexts, paillierPKN, ringPedersenPK, Ri, nil)
		assert.NoError(test, err)

		err = zkproof.Verify(proofParameter, contextI, kCiphertexts, paillierPKN, ringPedersenPK, Ri, nil)
		assert.NoError(test, err)
	}

	i := 0
	fmt.Printf("P[%d]: ProofParameter: %v\n", i, proofParameter)
	fmt.Printf("P[%d]: contextI: %v", i, contextI)
	fmt.Printf("P[%d]: round.temp.kCiphertexts[i]: %v\n", i, kCiphertexts)
	fmt.Printf("P[%d]: round.key.PaillierPKs[i].N: %v\n", i, paillierPKN)
	fmt.Printf("P[%d]: round.key.RingPedersenPKs[j].N: %v\n", i, ringPedersenPK.N)
	fmt.Printf("P[%d]: round.key.RingPedersenPKs[j].S: %v\n", i, ringPedersenPK.S)
	fmt.Printf("P[%d]: round.key.RingPedersenPKs[j].T: %v\n", i, ringPedersenPK.T)
	fmt.Printf("P[%d]: Ri.X: %v\n", i, Ri.X())
	fmt.Printf("P[%d]: Ri.Y: %v\n", i, Ri.Y())
	fmt.Printf("P[%d]: round.temp.k: %v\n", i, k)
	fmt.Printf("P[%d]: round.temp.rho: %v\n", i, rho)
}

func TestInner(test *testing.T) {
	Xx, _ := new(big.Int).SetString("39710103369699620907768546706720628819107908813746925126770888792345163639807", 10)
	Xy, _ := new(big.Int).SetString("23112279601404674396947307369672844175180851774459690019400076546526759584933", 10)
	Yx, _ := new(big.Int).SetString("29303606833423964122638638318493168050501763812939014177296538968701251506077", 10)
	Yy, _ := new(big.Int).SetString("18824829694871861307351535053417902000447879825881794755414471594880392491054", 10)
	G, _ := crypto.NewECPoint(edwards.Edwards(), edwards.Edwards().Params().Gx, edwards.Edwards().Params().Gy)
	X, _ := crypto.NewECPoint(G.Curve(), Xx, Xy)
	Y, _ := crypto.NewECPoint(G.Curve(), Yx, Yy)
	e, _ := new(big.Int).SetString("-1106682547535842970053541120473732360396479465055403577270271749594832416918", 10)
	z1, _ := new(big.Int).SetString("2462741941299769445472902294764399150006655258201471547387657936210106457779395943948164770404640497423365959782646012034570846264002549306638014453989345182496815027166382879236335845616151813384755098780214410942576601701934151", 10)

	YXexpe := X.ScalarMult(e)
	YXexpe, _ = YXexpe.Add(Y)

	gz1 := G.ScalarMult(z1)
	assert.Equal(test, gz1.X(), YXexpe.X())
	assert.Equal(test, gz1.Y(), YXexpe.Y())
}

func TestInner1(test *testing.T) {
	Xx, _ := new(big.Int).SetString("11877473636608284010367716296368282554950338177977662121408568727015652709966", 10)
	Xy, _ := new(big.Int).SetString("11334182879754312600865200567492457488369647841606112163680143926023626244096", 10)
	Yx, _ := new(big.Int).SetString("50913816759193278958216026253247576683866387517011351512821582546007931272104", 10)
	Yy, _ := new(big.Int).SetString("14891264352969064284269136353621689931091981973789925471797239490122140045780", 10)
	G, _ := crypto.NewECPoint(edwards.Edwards(), edwards.Edwards().Params().Gx, edwards.Edwards().Params().Gy)
	X, _ := crypto.NewECPoint(G.Curve(), Xx, Xy)
	Y, _ := crypto.NewECPoint(G.Curve(), Yx, Yy)
	e, _ := new(big.Int).SetString("-1575260799127347852161736736843846537779194160204870476099350057059590722711", 10)
	z1, _ := new(big.Int).SetString("2187835817991543976994557833011213237061332298054065695857747320026073464273285334754791326723786108692815490997859396275388784365706265531726519373757342323510966429113635270467930184681911713450313023607603826446789764542383356", 10)

	YXexpe := X.ScalarMult(e)
	YXexpe, _ = YXexpe.Add(Y)

	gz1 := G.ScalarMult(z1)
	assert.Equal(test, gz1.X(), YXexpe.X())
	assert.Equal(test, gz1.Y(), YXexpe.Y())
}

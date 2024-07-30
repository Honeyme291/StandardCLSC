package Chen;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;



public class chen {


    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }

    }

    public static Properties loadPropFromFile(String fileName) throws InterruptedException {
        Properties prop = new Properties();
        try (
                FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }

        return prop;
    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void main(String[] args) throws Exception {
        String rec = "rec@snnu.edu.com";
        String[] messages = new String[]{"111", "12345678", "01234567890123456789", "7777777777", "123", "1123", "123", "123", "123", "123"};
        String[] users = new String[]{"send@snnu.edu.com", "send1@snnu.edu.com", "send2@snnu.edu.com", "send3@snnu.edu.com", "send4@snnu.edu.com", "send5@snnu.edu.com", "send6@snnu.edu.com", "send7@snnu.edu.com", "send8@snnu.edu.com", "send9@snnu.edu.com"};
        String dir = "E:/java program/standard/database/Chen/";
        String pairingParametersFileName = "E:/java program/standard/database/Chen/a.properties";
        String publicParameterFileName = dir + "pub.properties";
        String mskFileName = dir + "msk.properties";
        String pkFileName = dir + "pk.properties";
        String skFileName = dir + "sk.properties";
        String signCryptFileName = dir + "signCrypt.properties";
        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            setup(pairingParametersFileName, publicParameterFileName, mskFileName);

            SecretKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            SecretKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            PartialKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, users[i], pkFileName, skFileName);
            PartialKeyGen(pairingParametersFileName, publicParameterFileName, mskFileName, rec, pkFileName, skFileName);
            signCrypt(pairingParametersFileName, publicParameterFileName, skFileName, pkFileName, messages[i], users[i], signCryptFileName,rec);
            Verify(pairingParametersFileName,publicParameterFileName,pkFileName,signCryptFileName,users[i],rec);
            UnSignCyption(pairingParametersFileName,publicParameterFileName,skFileName,signCryptFileName,pkFileName,users[i],rec);
            long end = System.currentTimeMillis();
            System.out.print("运行时间为");
            System.out.println(end - start);

        }
    }

    private static void Verify(String pairingParametersFileName, String publicParameterFileName, String pkFileName, String signCryptFileName, String user, String rec) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties pkp=loadPropFromFile(pkFileName);
        String Pstr1 = publicParams.getProperty("P");
        String P_pubistr1=publicParams.getProperty("P_pub");
        Element P1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties pkp1=loadPropFromFile(pkFileName);

        Properties sig = loadPropFromFile(signCryptFileName);
        String I1 =sig.getProperty("I"+user);

        Element I=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(I1.getBytes())).getImmutable();

        String sign1 =sig.getProperty("sign"+user);

        Element sign=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sign1.getBytes())).getImmutable();

        String TS1 = pkp.getProperty("T"+user);

        Element TS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TS1.getBytes())).getImmutable();

        String r1 =sig.getProperty("r"+user);

        Element r=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(r1.getBytes())).getImmutable();

        String QS1 = pkp.getProperty("Q"+user);

        Element QS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QS1.getBytes())).getImmutable();
        byte[] BH_1 = sha1(user+TS.toString()+P.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();


        Element option = P.powZn(sign);

        Element option1 = QS.powZn(H_1);

        Element option2 =(TS.add(P_pub.powZn(H_1))).powZn(H_1);

        Element option3 = (option1.add(option2)).powZn(r);

        Element Irec = option.sub(option3);

    }

    private static void UnSignCyption(String pairingParametersFileName, String publicParameterFileName, String skFileName, String signCryptFileName, String pkFileName ,String user, String rec) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String Pstr1 = publicParams.getProperty("P");
        String P_pubistr1=publicParams.getProperty("P_pub");
        Element P1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties pkp1=loadPropFromFile(pkFileName);
        Properties skp1=loadPropFromFile(skFileName);
        Properties sig = loadPropFromFile(signCryptFileName);

        String U1 =sig.getProperty("U"+user);

        Element U=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(U1.getBytes())).getImmutable();


        String xR1 =  skp.getProperty("x"+rec);

        Element xR = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xR1.getBytes())).getImmutable();

        String dR1 =  skp.getProperty("d"+rec);

        Element dR = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xR1.getBytes())).getImmutable();


        String TS1 = pkp.getProperty("T"+user);

        Element TS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TS1.getBytes())).getImmutable();

        byte[] BH_1 = sha1(user+TS.toString()+P.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();


        String QS1 = pkp.getProperty("Q"+user);

        Element QS = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QS1.getBytes())).getImmutable();

      Element option = U.powZn(H_1.mul(xR).add(H_1.mul(dR)));



    }

    private static void signCrypt(String pairingParametersFileName, String publicParameterFileName, String skFileName, String pkFileName, String messages, String user, String signCryptFileName, String rec) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        Element u = bp.getZr().newRandomElement().getImmutable();
        String Pstr1 = publicParams.getProperty("P");
        String P_pubistr1=publicParams.getProperty("P_pub");
        Element P1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties pkp1=loadPropFromFile(pkFileName);
        Properties skp1=loadPropFromFile(skFileName);
        String Q1S=pkp.getProperty("Q"+user);
        Element QS=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Q1S.getBytes())).getImmutable();

        String T1S = pkp.getProperty("T"+user);
        Element TS=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T1S.getBytes())).getImmutable();

        byte[] BH_1 = sha1(user+TS.toString()+P.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();
        String xS1=skp.getProperty("x"+user);
        Element xS=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xS1.getBytes())).getImmutable();

        String dS1 = skp.getProperty("d"+user);
        Element dS=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(dS1.getBytes())).getImmutable();

        String Q1R=pkp.getProperty("Q"+rec);
        Element QR=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Q1R.getBytes())).getImmutable();

        String T1R = pkp.getProperty("T"+rec);
        Element TR=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T1R.getBytes())).getImmutable();

        Element U = QS.add(TS).add(P_pub.powZn(H_1)).powZn(u);

        byte[] BH_j = sha1(user+TR.toString()+P.toString()+P_pub.toString());
        Element H_j=bp.getZr().newElementFromHash(BH_j,0,BH_j.length).getImmutable();

        Element option = u.mul(xS.add(dS));

        Element option1 = QR.powZn(H_j);

        Element option2 = QR.powZn(H_j).add((TR.add(P_pub.powZn(H_j))).powZn(H_1));
        Element option3 = (option1.add(option2)).powZn(option);
        byte [] BH_2 = sha1(user+U.toString()+option3.toString());

        Element Y=bp.getZr().newElementFromHash(BH_2,0,BH_2.length).getImmutable();
        byte[] messageByte = messages.getBytes();
        byte[] ci = new byte[messageByte.length];
        for (int j = 0; j < messageByte.length; j++){
            ci[j] = (byte)(messageByte[j] ^ BH_2[j]);
        }
        Element c = bp.getZr().newElementFromHash(ci,0,ci.length);

        Element k = bp.getZr().newRandomElement().getImmutable();

        Element I = P.powZn(k);

        byte[] Br = sha1(I.toString()+c.toString());
        Element r=bp.getZr().newElementFromHash(Br,0,Br.length).getImmutable();


        Element sign = (xS.mul(H_1).add(H_j.mul(dS))).mul(r).add(k);


        Properties sigC=loadPropFromFile(signCryptFileName);
        sigC.setProperty("U"+user, Base64.getEncoder().encodeToString(U.toBytes()));
        sigC.setProperty("r"+user, Base64.getEncoder().encodeToString(r.toBytes()));
        sigC.setProperty("C"+user, Base64.getEncoder().encodeToString(ci.toString().getBytes()));
        sigC.setProperty("I"+user, Base64.getEncoder().encodeToString(I.toBytes()));
        sigC.setProperty("sign"+user, Base64.getEncoder().encodeToString(sign.toBytes()));


        storePropToFile(sigC,signCryptFileName);

    }

    private static void PartialKeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws NoSuchAlgorithmException, InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String Pstr1 = publicParams.getProperty("P");
        String P_pubistr1=publicParams.getProperty("P_pub");
        Element P1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties pkp1=loadPropFromFile(pkFileName);
        Properties skp1=loadPropFromFile(skFileName);
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();
        Element a = bp.getZr().newRandomElement().getImmutable();
        Element T = P.powZn(a).getImmutable();
        String Q1=pkp.getProperty("Q"+user);
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Q1.getBytes())).getImmutable();
        byte[] BH_1 = sha1(user+Q.toString()+P.toString()+P_pub.toString());
        Element H_1=bp.getZr().newElementFromHash(BH_1,0,BH_1.length).getImmutable();

        Element d = a.add(s.mul(H_1));
        //将公钥存储起来。
        pkp.setProperty("T"+user,Base64.getEncoder().encodeToString(T.toBytes()));
        skp.setProperty("d"+user,Base64.getEncoder().encodeToString(d.toBytes()));
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);

    }
    private static void SecretKeyGen(String pairingParametersFileName, String publicParameterFileName, String mskFileName, String user, String pkFileName, String skFileName) throws InterruptedException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties publicParams = loadPropFromFile(publicParameterFileName);
        String Pstr = publicParams.getProperty("P");
        String P_pubistr=publicParams.getProperty("P_pub");
        Element P=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties mskPro = loadPropFromFile(mskFileName);
        Properties pkp=loadPropFromFile(pkFileName);
        Properties skp=loadPropFromFile(skFileName);
        String Pstr1 = publicParams.getProperty("P");
        String P_pubistr1=publicParams.getProperty("P_pub");
        Element P1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(Pstr.getBytes())).getImmutable();
        Element P_pub1=bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubistr.getBytes())).getImmutable();
        Properties pkp1=loadPropFromFile(pkFileName);
        Properties skp1=loadPropFromFile(skFileName);
        String s_istr=mskPro.getProperty("s");
        Element s=bp.getZr().newElementFromBytes(Base64.getDecoder().decode(s_istr)).getImmutable();
        Element x = bp.getZr().newRandomElement().getImmutable();
        Element Q = P.powZn(x).getImmutable();
        //将公钥存储起来。
        pkp.setProperty("Q"+user,Base64.getEncoder().encodeToString(Q.toBytes()));
        skp.setProperty("x"+user,Base64.getEncoder().encodeToString(x.toBytes()));
        storePropToFile(pkp,pkFileName);
        storePropToFile(skp,skFileName);
    }
    private static void setup(String pairingParametersFileName, String publicParameterFileName, String mskFileName) {

        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        //设置KGC主私钥s

        Element s = bp.getZr().newRandomElement().getImmutable();
        Properties mskProp = new Properties();
        mskProp.setProperty("s", Base64.getEncoder().encodeToString(s.toBytes()));
        storePropToFile(mskProp, mskFileName);

        //设置主公钥K_pub和公开参数
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();
        Properties pubProp = new Properties();
        pubProp.setProperty("P", Base64.getEncoder().encodeToString(P.toBytes()));
        pubProp.setProperty("P_pub", Base64.getEncoder().encodeToString(P_pub.toBytes()));
        storePropToFile(pubProp, publicParameterFileName);
    }
}

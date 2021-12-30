package tool.encryptionAndDecryption;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.UUID;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;



public class GAData {
	private String deviceCode="";
	private String yzmc="";
	private String yzbm="";
	private String yzzzdwbm="";
	private String yzlxdm="";
	private String jbr_xm="";
	private String jbr_zjlx="";
	private String jbr_zjhm="";
	private String zzrq="";
	private String yzsydw_dwmc="";
	private String yzsydw_dwssmzwzmc="";
	private String yzsydw_dwywmc="";
	private String yzzzdw_dwmc="";
	private String yzzzdw_dwssmzwzmc="";
	private String yzzzdw_dwywmc="";
	private String yzsydw_tyshxydm="";
	
	private GAData() {}
	
	public GAData(String yzmc, String yzbm, String yzzzdwbm, String yzlxdm, String jbr_xm,
			String jbr_zjlx, String jbr_zjhm, String zzrq, String yzsydw_dwmc, String yzsydw_dwssmzwzmc,
			String yzsydw_dwywmc, String yzzzdw_dwmc, String yzzzdw_dwssmzwzmc, String yzzzdw_dwywmc,
			String yzsydw_tyshxydm) {
		super();
		
		this.yzmc = yzmc==null?"":yzmc;
		this.yzbm = yzbm==null?"":yzbm;
		this.yzzzdwbm = yzzzdwbm==null?"":yzzzdwbm;
		this.yzlxdm = yzlxdm==null?"":yzlxdm;
		this.jbr_xm = jbr_xm==null?"":jbr_xm;
		this.jbr_zjlx = jbr_zjlx==null?"":jbr_zjlx;
		this.jbr_zjhm = jbr_zjhm==null?"":jbr_zjhm;
		this.zzrq = zzrq==null?"":zzrq;
		this.yzsydw_dwmc = yzsydw_dwmc==null?"":yzsydw_dwmc;
		this.yzsydw_dwssmzwzmc = yzsydw_dwssmzwzmc==null?"":yzsydw_dwssmzwzmc;
		this.yzsydw_dwywmc = yzsydw_dwywmc==null?"":yzsydw_dwywmc;
		this.yzzzdw_dwmc = yzzzdw_dwmc==null?"":yzzzdw_dwmc;
		this.yzzzdw_dwssmzwzmc = yzzzdw_dwssmzwzmc==null?"":yzzzdw_dwssmzwzmc;
		this.yzzzdw_dwywmc = yzzzdw_dwywmc==null?"":yzzzdw_dwywmc;
		this.yzsydw_tyshxydm = yzsydw_tyshxydm==null?"":yzsydw_tyshxydm;
	}
	public static GAData getObjFormAsn1(byte[] ans1){
		GAData gadata=new GAData();
		/*try{
			GADataAsn1 asn1obj=GADataAsn1.getdecoded(ans1);
			gadata.deviceCode=asn1obj.deviceCode.getValue();
			gadata.jbr_xm=new String(asn1obj.jbr_xm.getValue(),"utf-8");
			
			//其他内容先省略，获取方式同上
		}catch(Exception e){
			e.printStackTrace();
		}*/
		try {
			DLSequence sequence = (DLSequence) (new ASN1InputStream(new ByteArrayInputStream(ans1))).readObject();
			gadata.deviceCode=((DERIA5String)sequence.getObjectAt(0)).getString();
			gadata.yzmc=((DERUTF8String)sequence.getObjectAt(1)).getString();
			gadata.yzbm=((DERIA5String)sequence.getObjectAt(2)).getString();
			gadata.yzzzdwbm=((DERIA5String)sequence.getObjectAt(3)).getString();
			gadata.yzlxdm=((DERIA5String)sequence.getObjectAt(4)).getString();
			gadata.jbr_xm=((DERUTF8String)sequence.getObjectAt(5)).getString();
			gadata.jbr_zjlx=((DERIA5String)sequence.getObjectAt(6)).getString();
			gadata.jbr_zjhm=((DERIA5String)sequence.getObjectAt(7)).getString();
			gadata.zzrq=((DERIA5String)sequence.getObjectAt(8)).getString();
			gadata.yzsydw_dwmc=((DERUTF8String)sequence.getObjectAt(9)).getString();
			gadata.yzsydw_dwssmzwzmc=((DERUTF8String)sequence.getObjectAt(10)).getString();
			gadata.yzsydw_dwywmc=((DERUTF8String)sequence.getObjectAt(11)).getString();
			gadata.yzzzdw_dwmc=((DERUTF8String)sequence.getObjectAt(12)).getString();
			gadata.yzzzdw_dwssmzwzmc=((DERUTF8String)sequence.getObjectAt(13)).getString();
			gadata.yzzzdw_dwywmc=((DERUTF8String)sequence.getObjectAt(14)).getString();
			gadata.yzsydw_tyshxydm=((DERUTF8String)sequence.getObjectAt(15)).getString();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
   		
		
		return gadata;
	}
	public  byte[]  getEncoded() throws IOException {
		ASN1EncodableVector	data=new ASN1EncodableVector();
		data.add(new DERIA5String(deviceCode));
		data.add(new DERUTF8String(yzmc));
		data.add(new DERIA5String(yzbm));
		data.add(new DERIA5String(yzzzdwbm));
		data.add(new DERIA5String(yzlxdm));
		data.add(new DERUTF8String(jbr_xm));
		data.add(new DERIA5String(jbr_zjlx));
		data.add(new DERIA5String(jbr_zjhm));
		data.add(new DERIA5String(zzrq));
		data.add(new DERUTF8String(yzsydw_dwmc));
		data.add(new DERUTF8String(yzsydw_dwssmzwzmc));
		data.add(new DERUTF8String(yzsydw_dwywmc));
		data.add(new DERUTF8String(yzzzdw_dwmc));
		data.add(new DERUTF8String(yzzzdw_dwssmzwzmc));
		data.add(new DERUTF8String(yzzzdw_dwywmc));
		data.add(new DERUTF8String(yzsydw_tyshxydm));
		return new DERSequence(data).getEncoded();
	}
	
	public String getDeviceCode() {
		return deviceCode;
	}
	public void setDeviceCode(String deviceCode) {
		this.deviceCode = deviceCode;
	}
	public String getYzmc() {
		return yzmc;
	}
	public void setYzmc(String yzmc) {
		this.yzmc = yzmc;
	}
	public String getYzbm() {
		return yzbm;
	}
	public void setYzbm(String yzbm) {
		this.yzbm = yzbm;
	}
	public String getYzzzdwbm() {
		return yzzzdwbm;
	}
	public void setYzzzdwbm(String yzzzdwbm) {
		this.yzzzdwbm = yzzzdwbm;
	}
	public String getYzlxdm() {
		return yzlxdm;
	}
	public void setYzlxdm(String yzlxdm) {
		this.yzlxdm = yzlxdm;
	}
	public String getJbr_xm() {
		return jbr_xm;
	}
	public void setJbr_xm(String jbr_xm) {
		this.jbr_xm = jbr_xm;
	}
	public String getJbr_zjlx() {
		return jbr_zjlx;
	}
	public void setJbr_zjlx(String jbr_zjlx) {
		this.jbr_zjlx = jbr_zjlx;
	}
	public String getJbr_zjhm() {
		return jbr_zjhm;
	}
	public void setJbr_zjhm(String jbr_zjhm) {
		this.jbr_zjhm = jbr_zjhm;
	}
	public String getZzrq() {
		return zzrq;
	}
	public void setZzrq(String zzrq) {
		this.zzrq = zzrq;
	}
	public String getYzsydw_dwmc() {
		return yzsydw_dwmc;
	}
	public void setYzsydw_dwmc(String yzsydw_dwmc) {
		this.yzsydw_dwmc = yzsydw_dwmc;
	}
	public String getYzsydw_dwssmzwzmc() {
		return yzsydw_dwssmzwzmc;
	}
	public void setYzsydw_dwssmzwzmc(String yzsydw_dwssmzwzmc) {
		this.yzsydw_dwssmzwzmc = yzsydw_dwssmzwzmc;
	}
	public String getYzsydw_dwywmc() {
		return yzsydw_dwywmc;
	}
	public void setYzsydw_dwywmc(String yzsydw_dwywmc) {
		this.yzsydw_dwywmc = yzsydw_dwywmc;
	}
	public String getYzzzdw_dwmc() {
		return yzzzdw_dwmc;
	}
	public void setYzzzdw_dwmc(String yzzzdw_dwmc) {
		this.yzzzdw_dwmc = yzzzdw_dwmc;
	}
	public String getYzzzdw_dwssmzwzmc() {
		return yzzzdw_dwssmzwzmc;
	}
	public void setYzzzdw_dwssmzwzmc(String yzzzdw_dwssmzwzmc) {
		this.yzzzdw_dwssmzwzmc = yzzzdw_dwssmzwzmc;
	}
	public String getYzzzdw_dwywmc() {
		return yzzzdw_dwywmc;
	}
	public void setYzzzdw_dwywmc(String yzzzdw_dwywmc) {
		this.yzzzdw_dwywmc = yzzzdw_dwywmc;
	}
	public String getYzsydw_tyshxydm() {
		return yzsydw_tyshxydm;
	}
	public void setYzsydw_tyshxydm(String yzsydw_tyshxydm) {
		this.yzsydw_tyshxydm = yzsydw_tyshxydm;
	}
	
	public static void main(String[] args) throws IOException {
		System.out.println(UUID.randomUUID().toString());
		
		/*GAData gaData= new GAData("sbh", "yzmc", "yzbm", "yzzzdwbm", "yzlxdm", "jbr_xm", "jbr_zjlx", "jbr_zjhm", "zzrq", "yzsydw_dwmc", "yzsydw_dwssmzwzmc", "yzsydw_dwywmc", "yzzzdw_dwmc", "yzzzdw_dwssmzwzmc", "yzywmc_dwywmc", "yzsydw_tyshxydn");
		byte[] bx=gaData.getEncoded();
		System.out.println(Base64.encodeBase64String(bx));	
		GAData f=GAData.getObjFormAsn1(bx);
		System.out.println(f);*/
	}
}

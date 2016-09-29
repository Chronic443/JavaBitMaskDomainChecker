import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.io.*;
import org.apache.commons.net.whois.WhoisClient;

class HaveFun {
	
	//Check if the domain is available #5
	public static void checkDom(ArrayList<String> doms)
	{
		ArrayList<String> match = new ArrayList<String>();
		/*
		 * Add Patterns
		 */
		match.add("NOT FOUND");
		match.add("No match for");
		match.add("Not fo");
		match.add("No Data Fou");
		match.add("has not been regi");
		match.add("No entri");
		match.add("Not AVAILABLE");
		
		Map<String,String> srvList = new HashMap<String,String>();
		ArrayList<String> urlSrvUniq = new ArrayList<String>();
		
		for(int i_00=0; i_00<doms.size(); i_00++)
		{
			try
			{
				BufferedReader br00 = new BufferedReader(new FileReader("/home/chronic/whoisSrv/ExtSrvList"));
				BufferedReader br01 = new BufferedReader(new FileReader("/home/chronic/whoisSrv/noExtWhoisList"));
				
				String line00, line01;
				
				while((line00 = br00.readLine()) != null && (line01 = br01.readLine()) != null)
					srvList.put(line00, line01);
				
				br00.close();
				br01.close();
				
				ArrayList<String> urlSrv = new ArrayList<String>();
				String ext = "";
				for(int i_01=0; i_01<doms.size(); i_01++)
				{
					for(int j_00=0; j_00<doms.get(i_01).length(); j_00++)
					{
						if(doms.get(i_01).charAt(j_00) == '.')
						{
							ext = doms.get(i_01).substring(j_00+1, doms.get(i_01).length());
							urlSrv.add(srvList.get(ext));
							break;
						}
						
					}
				}
				
				urlSrv.removeAll(Collections.singleton(null));
				Collections.sort(urlSrv);
				
				
				for(int i_02=0; i_02<urlSrv.size(); i_02++)
				{
					if(!urlSrvUniq.contains(urlSrv.get(i_02)))
						urlSrvUniq.add(urlSrv.get(i_02));	
				}
			}
			catch(Exception e)
			{
				System.out.println("Line 59 " + e);
			}
				
			for(int j_01=0; j_01<urlSrvUniq.size(); j_01++)
			{
				try
				{
					StringBuilder res = new StringBuilder("");
					WhoisClient whois = new WhoisClient();
					whois.connect(urlSrvUniq.get(j_01));
					String whoisData = whois.query("=" + doms.get(i_00));
					
					res.append(whoisData);
					whois.disconnect();
					
					String result = res.toString();
				
					boolean test = false;
					for(int i_03=0; i_03<match.size(); i_03++)
					{
						if(result.contains(match.get(i_03)))
						{
							test = true;
							break;
						}
						
					}
					if(test == true)
						System.out.println("QUERY SERVER: " + urlSrvUniq.get(j_01) + "\n" + 
					"DOMAIN: " + doms.get(i_00) + " Might be available." + "\n");
					
				}
				catch(Exception e)
				{
					System.out.println("Line 105 " + e);
				}
			}		
		}
	}
	
	//Converts from bin to text #4 
	public static ArrayList<String> candidatesDom(ArrayList<String> can)
	{
		ArrayList<String> canList = new ArrayList<String>();
		
		for(int i=0; i<can.size(); i++)
		{
			if(can.get(i).length() == 7)
			{
				String reverse00 = new StringBuffer(can.get(i)).reverse().toString();
				reverse00 += "0";
				String reverse01 = new StringBuffer(reverse00).reverse().toString();
				can.remove(i);
				can.add(i, reverse01);
			}
			else if(can.get(i).length() == 6)
			{
				String reverse00 = new StringBuffer(can.get(i)).reverse().toString();
				reverse00 += "00";
				String reverse01 = new StringBuffer(reverse00).reverse().toString();
				can.remove(i);
				can.add(i, reverse01);
			}
		}
		
		for(int j=0; j<can.size(); j++)
		{
			String tmpStr01 ="";
			String tmpStr00 = can.get(j);
			for(int i=0; i<tmpStr00.length()/8; i++)
			{
				int a = Integer.parseInt(tmpStr00.substring(8*i,(i+1)*8),2);
				tmpStr01 += (char)(a);
			}	
			canList.add(tmpStr01);
		}
		
		return canList;
	}
	
	//Generates a list of candidate URL-s #2 
	public static ArrayList<String> candidatesBin(String binDom)
	{
		ArrayList<String> candidates = new ArrayList<String>();
		
		for(int i=0; i<binDom.length(); i++)
		{
			if(binDom.charAt(i) == '0')
			{
				char[] tmpChar = binDom.toCharArray();
				tmpChar[i] = '1';
				String tmpStr = new String(tmpChar);
				candidates.add(tmpStr);
			}
			else if(binDom.charAt(i) == '1')
			{
				char[] tmpChar = binDom.toCharArray();
				tmpChar[i] = '0';
				String tmpStr = new String(tmpChar);
				candidates.add(tmpStr);
			}
		}
		
		
		return candidates;
	}
	
	//Gets the bit mask of the domain #1
	public static String bitMaskOfTheDomain(String Dom)
	{
		ArrayList<String> bitMask = new ArrayList<String>();
		String tmp = "";
		char[] tmpChar = Dom.toCharArray();
		
			for(int i=0; i<tmpChar.length; i++)
			{
				tmp += Integer.toBinaryString(tmpChar[i]);
				bitMask.add(tmp);
				tmp = "";
			}
		
		String bitMaskStr = "";
		for(int i=0; i<bitMask.size(); i++)
		{
			if(bitMask.get(i).length() == 7)
			{
				String reverse00 = new StringBuffer(bitMask.get(i)).reverse().toString();
				reverse00 += "0";
				String reverse01 = new StringBuffer(reverse00).reverse().toString();
				bitMask.remove(i);
				bitMask.add(i, reverse01);
				bitMaskStr += bitMask.get(i); 
			}
			else if(bitMask.get(i).length() == 6)
			{
				String reverse00 = new StringBuffer(bitMask.get(i)).reverse().toString();
				reverse00 += "00";
				String reverse01 = new StringBuffer(reverse00).reverse().toString();
				bitMask.remove(i);
				bitMask.add(i, reverse01);
				bitMaskStr += bitMask.get(i);
			}
			else{bitMaskStr += bitMask.get(i);}
		}
		
		return bitMaskStr;
	}
	
	//Remove illegal chars #3
 	public static ArrayList<String> validDom(ArrayList<String> binDom)
	{
		/* ILLEGAL CHARS
		 * + . , | ! ' " £ $ % & / () <> [] {} = ? ^ * ; : # @ _
		 * length 3-63
		 * Cannot start with -
		 * Cannot end with -
		 * Can have - in the middle
		 * 
		 * LEGAL CHARS
		 * numbers, letters and - in the middle 
		 */
		
		//26 * 2 letters
		//10 numbers
		//1 - 
				
		ArrayList<String> txtDom = new ArrayList<String>(candidatesDom(binDom));
		ArrayList<String> txtDomValid = new ArrayList<String>();
		
		for(int i=0; i<txtDom.size(); i++)
		{
			String stripped=txtDom.get(i).replaceAll("[^a-zA-Z0-9-.]","");
			String strippedLower = stripped.toLowerCase();
				if(strippedLower.charAt(0) == '-' || strippedLower.charAt(strippedLower.length()-1) == '-' ||
						strippedLower.length() != txtDom.get(i).length())
					continue;
				else
					txtDomValid.add(strippedLower);			
		}
		
		ArrayList<String> uniqList = new ArrayList<String>();
		
		for(int i=0; i<txtDomValid.size(); i++)
		{
			if(uniqList.contains(txtDomValid.get(i)))
				continue;
			else
				uniqList.add(txtDomValid.get(i));
		}
		
		return uniqList;
	}
	
	public static void main(String args[])
	{	
		checkDom(validDom(candidatesBin(bitMaskOfTheDomain("facebook.com"))));	
	}
}


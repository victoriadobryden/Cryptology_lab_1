#ifdef WIN32
#include <afxwin.h>         // MFC core and standard components
#include <afxext.h>         // MFC extensions
#endif
#include "Des.h"
#include <stdlib.h>
#include <stdio.h>

void  stktranspose(char *data,int *t,int n)
{
	char x[64];
	int i;

	memcpy(x,data,64);
	for(i=0;i<n;i++) data[i]=x[t[i]-1];
}
void  stkcompress(char *str64,char *str8) /* compress 64-chars to 8-chars*/
{
	int i,j;

	for(i=0;i<8;i++)
	{
		str8[i]='\0';
		for(j=0;j<8;j++)
			str8[i]=(str8[i]<<1)|str64[i*8+j];
	}
}

void  stkrotate(char *x,int s)
{
	char x0,x1,x2,x3;

	x0=x[0];
	x1=x[1];
	x2=x[28];
	x3=x[29];
	memcpy(x,&x[s],54);
	if (s==1)
	{
		x[54]=x[55];
		x[27]=x0;
		x[55]=x2;
	}
	else
	{
		x[26]=x0;
		x[27]=x1;
		x[54]=x2;
		x[55]=x3;
	}
}

void  stkf(char *key,char *a,char *x)	
{
	int r,k,j;
	char e[48],y[48];

	memcpy(e,a,32);
	stktranspose(e,etr,48);
	for(j=0;j<48;j++) y[j]=e[j]^key[j];
	for(k=0;k<8;k++)
	{
		r=32*y[6*k]+16*y[6*k+5]+8*y[6*k+1]+4*y[6*k+2]+2*y[6*k+3]+y[6*k+4];
		x[4*k]=(char)(s[k][r]/8)%2;
		x[4*k+1]=(char)(s[k][r]/4)%2;
		x[4*k+2]=(char)(s[k][r]/2)%2;
		x[4*k+3]=(char)s[k][r]%2;
	}
	stktranspose(x,ptr,32);
}

void  stkdes_de(char *ciphertext,char *key,char *plaintext) 
{
	int i,j;
	char a[64],b[64],ikey[16][64],kk[64],x[64];

	for(i=0;i<8;i++)	 /* expand 8-chars to 64-chars*/ 
		for(j=0;j<8;j++)
	{
		kk[i*8+j]=(key[i]>>(7-j))&0x1;
		a[i*8+j]=(ciphertext[i]>>(7-j))&0x1;
	}
	stktranspose(a,InitialTr,64);
	stktranspose(kk,keyTr1,56);
	for(i=0;i<16;i++)
	{
		stkrotate(kk,keyshift[i]);
		memcpy(ikey[i],kk,64);
	}
	stktranspose(ikey[15],keyTr2,48);
	memcpy(b,a,32);
	memcpy(a,&a[32],32);
	stkf(ikey[15],a,x);
	for(j=0;j<32;j++)
		a[j]=b[j]^x[j];
	for(i=1;i<16;i++)
	{
		memcpy(b,&a[32],32);
		memcpy(&a[32],a,32);
		stktranspose(ikey[15-i],keyTr2,48);
		stkf(ikey[15-i],a,x);
		for(j=0;j<32;j++)
			a[j]=b[j]^x[j];
	}
	stktranspose(a,FinalTr,64);
	stkcompress(a,plaintext);
}

void  stkdes_en(char *ciphertext,char *key,char *plaintext) 
{
;
}

short  stkAscToHexFunc(char * Hex, char * asc, int AscLen)
{
	char * HexPtr = Hex;
	short i;
	for(i = 0; i < AscLen; i++)
	{
		*HexPtr = asc[i] << 4;
		if (!(asc[i]>='0' && asc[i]<='9'))
			*HexPtr += (char)0x90;
		i++;
		*HexPtr |= (asc[i] & 0x0F);
		if (!(asc[i]>='0' && asc[i]<='9'))
			*HexPtr += 0x09;
		HexPtr++;
	}
	return 1;
}

void  stkDES_CRYPT(short en_mode,char *key,char *crypt_text,short text_len)
{
	short i;
	if (en_mode)
    {
	/*	crypt_text[text_len]='\0';*/
		for(i=0;i<text_len;i+=8)
			stkdes_en(&crypt_text[i],key,&crypt_text[i]);
    }
	else
	{
	/*	crypt_text[text_len]='\0'; */
		for(i=0;i<text_len;i+=8)/*Lqf 1998.5.18 */
			stkdes_de(&crypt_text[i],key,&crypt_text[i]);/*Lqf 1998.5.18*/
	}
}

void stkhextoasc(char **Hex, char *asc, int HexLen)
{
	int i;
	char *AscPtr = asc;
	char *HexPtr = *Hex;
	char Temp;

	for(i = 0; i < HexLen; i++)
	{
		Temp = (*HexPtr & 0xf0) >> 4;
		if (Temp < 10)
			*AscPtr = 0x30 + Temp;
		else
			*AscPtr = 0x37 + Temp;
		AscPtr++;
		Temp = *HexPtr & 0x0f;
		if (Temp < 10)
			*AscPtr = 0x30 + Temp;
		else
			*AscPtr = 0x37 + Temp;
		AscPtr++;
		HexPtr++;
	}
	*Hex = HexPtr; 
}

short  stkDecryptPin(char *Pin,char *Zpk)
{
	short i;
	char *pin_ptr;
	char zpk[9],oldpin[9],newpin[9];

//        errlog(0, Pin);
	memcpy(oldpin,Pin,8); /* gjk 2000.6.16 */
	stkAscToHexFunc((char*)zpk, (char*)Zpk, 16);

	stkDES_CRYPT(0,zpk,oldpin,8);
//        errlog(0, oldpin);
	pin_ptr = oldpin;
        stkhextoasc((char **)&pin_ptr,Pin,8);
//        errlog(0, Pin);
	return 1;
}


short  stkEncryptPin(char *Pin, char *Zpk)
{
	short i;
	char *pin_ptr;
	char zpk[9],Oldpin[17], oldpin[9];

        memcpy(Oldpin, "06", 2);
	memcpy(Oldpin +2,Pin,6); 
        memset(Oldpin +8,'F', 8);
//        errlog(0, Oldpin);
//        errlog(0, Zpk);
        stkAscToHexFunc((char *)oldpin, (char *)Oldpin, 16); 
	stkAscToHexFunc((char*)zpk, (char*)Zpk, 16);

	stkDES_CRYPT(1,zpk,oldpin, 8);
        memcpy(Pin, oldpin, 8);
//        errlog(0, Pin);
	return 1;
}


short stkGenMac(char *mac_data,int len,char *zak,char *mac)
{
	/*ANSI X9.9 argorithm */
	char xData[9],*xDataptr;
	char Kmac[9];
	int i,j;
        xDataptr=xData;  
	stkAscToHexFunc((char*)Kmac, (char*)zak, 16);
/*	stkDES_CRYPT(0,LMK,Kmac,8);  gjk 2000.6.16 */
	memset(xData,0,8);
	for (i =0; i<8;i++) xData[i] ^= mac_data[i];
	for (i = 8; i < len; i += 8)
	{
		stkDES_CRYPT(1,Kmac,xData,8);
		for( j=0;j<8;j++)
		{
			if (i+j<len)
				xData[j] ^= mac_data[i+j];
			else
				xData[j] ^= 0;
		}
	}
	stkDES_CRYPT(1,Kmac,xData,8);
    stkhextoasc((char **)&xDataptr,(char*)mac,8);
	return 0;
}


char *stkGenDes(char *text, char *key)
{
	int i;
	int text_len;

	text_len = strlen((char*)text);
	for(i=0;i<text_len;i+=8)
		stkdes_en(&text[i],key,&text[i]);

	return text;
}

char *stkDecDes(char *text, char *key)
{
	int i;
	int text_len;

	text_len = strlen((char*)text);
	for(i=0;i<text_len;i+=8)
		stkdes_de(&text[i],key,&text[i]);

	return text;
}

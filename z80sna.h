#ifndef __Z80SNA_H__
#define __Z80SNA_H__

#define MAX_NAME 16


#pragma pack(push, 1)
struct sna_hdr {
	unsigned char	r_I;
	unsigned short	r_HL_alt, r_DE_alt, r_BC_alt, r_AF_alt;
	unsigned short	r_HL, r_DE, r_BC, r_IY, r_IX;
	unsigned char	int_flags;
	unsigned char	r_R;
	unsigned short	r_AF, r_SP;
	unsigned char	IM;
	unsigned char	pFE;
};

struct sna_hdr_ext {
	unsigned short r_PC;
	unsigned char p7FFD;
	unsigned char trdos;
};
#pragma pack(pop)

#endif

/*
 *      Interactive disassembler (IDA)
 *      Copyright (c) 1990-98 by Ilfak Guilfanov.
 *                        E-mail: ig@datarescue.com
 *      SNA loader v0.01
 *      by mr287cc^8bit-bay
 *                        E-mail: wecleman@gmail.com
  *
 */

 /*
		 SNA (ZX Spectrum snapshot) file loader
 */

#define PAGE_SIZE 0x4000
#define FIXED_PAGE 2

#include <ida.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <idp.hpp>
#include <diskio.hpp>
#include <entry.hpp>

#include "z80sna.h"

static sna_hdr _hdr;
static sna_hdr_ext _hdr_ext;

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
int idaapi accept_file(qstring *fileformatname, qstring *processor, linput_t *li, const char *filename)
{
	qlseek(li, 0, SEEK_SET);
	
	if (qlread(li, &_hdr, sizeof(_hdr)) != sizeof(_hdr)) return(0);

	unsigned int sna_size = qlsize(li);
	

	if (sna_size == 0xC01B)
	{
		fileformatname->clear();
		fileformatname->append("ZX Spectrum 48 shapshot file");
		return(1);
	}
	else
		if (sna_size == 0x2001F || sna_size == 0x2401F)
		{
			fileformatname->clear();
			fileformatname->append("ZX Spectrum 128 shapshot file");
			return(1);
		}
	else
		return(0);


}

static void make_array(ea_t addr, int datatype, const char *name, asize_t size) {
	const array_parameters_t array_params = { AP_ARRAY, 32 , 0 };

	switch (datatype) {
	case 1: create_byte(addr, size); break;
	case 2: create_word(addr, size); break;
	case 4: create_dword(addr, size); break;
	}
	set_array_parameters(addr, &array_params);
	set_name(addr, name);
}

//--------------------------------------------------------------------------
//
//      load file into the database.
//
void idaapi load_file(linput_t *li, ushort /*neflag*/, const char * /*fileformatname*/)
{
	unsigned int ea, pages, i;
	unsigned char high16k_bank;
	unsigned char videobank;

	sel_t sel = 1;

	if (ph.id != PLFM_Z80)
		set_processor_type("z80", SETPROC_LOADER);

	qlseek(li, 0, SEEK_SET);

	int sna_length = qlsize(li); // Get file size

	// Load header, first 27 bytes
	if (qlread(li, &_hdr, sizeof(_hdr)) != sizeof(_hdr)) loader_failure();


	// Add 48k segments
	if (!add_segm(0, 0x4000, 0x4000 + PAGE_SIZE * 3, "RAM", "CODE")) loader_failure();

	create_filename_cmt();

	qlseek(li, sizeof(_hdr), SEEK_SET);
	set_selector(sel, 0);
	
	// Read 3 pages
	file2base(li, qltell(li), 0x4000, 0x4000 + PAGE_SIZE * 3, FILEREG_PATCHABLE);
	
	switch (sna_length) {
	case 131103:
		pages = 5;
		break;
	case 147487:
		pages = 6;
		break;
	default:
		pages = 0;
	}

	if (pages) {
		// Load extended header
		if (qlread(li, &_hdr_ext, sizeof(_hdr_ext)) != sizeof(_hdr_ext)) loader_failure();

		high16k_bank = _hdr_ext.p7FFD & 7;
		if (_hdr_ext.p7FFD & 8)
			videobank = 7;
		else
			videobank = 5;

		msg("high bank = %i, videopage = %i\n", high16k_bank, videobank);

		char pagename[MAX_NAME];

		ea = 0x10000;
		for (i = 0; i < 8; i++) {
			if (i != high16k_bank && i != videobank && i!=FIXED_PAGE) {
				set_selector(sel, ea >> 4);
				ea += 0xC000;
				qsnprintf(pagename, MAX_NAME, "PAGE%01X", i);
				if (!add_segm(sel, ea, ea + PAGE_SIZE, pagename, "CODE")) loader_failure();
				file2base(li, qltell(li), ea, ea + PAGE_SIZE, FILEREG_PATCHABLE);
				sel++;
				ea += 0x10000;
			}
		}
	}

	inf.af =
	AF_FIXUP | //   0x0001          // Create offsets and segments using fixup info
	AF_MARKCODE | //   0x0002          // Mark typical code sequences as code
	AF_UNK | //   0x0004          // Delete instructions with no xrefs
	AF_CODE | //   0x0008          // Trace execution flow
	AF_PROC | //   0x0010          // Create functions if call is present
	AF_USED | //   0x0020          // Analyze and create all xrefs
	AF_FLIRT | //   0x0040          // Use flirt signatures
	AF_PROCPTR | //   0x0080          // Create function if data xref data->code32 exists
	AF_NULLSUB | //   0x0200          // Rename empty functions as nullsub_...
	AF_IMMOFF | //   0x2000          // Convert 32bit instruction operand to offset
	AF_DREFOFF; //   0x4000          // Create offset if data xref to seg32 exists
	inf.af2 = 0;

	// Make array for screen data, 32 bytes per line
	make_array(0x4000, 1, "SCREEN_DATA", 0x1800);

	// Make array for screen attributes, 32 bytes per row
	make_array(0x5800, 1, "SCREEN_ATTRS", 0x300);
	
	// Add stack comment
	add_extra_cmt(_hdr.r_SP, 0, "Stack (above)");

	// Add stack comment (program)
	add_pgm_cmt("Stack Ptr   : 0x%X", _hdr.r_SP);

	// SNA 128 info
	if (pages) {
		// Add pages info
		add_pgm_cmt("Screen page : %d", videobank);
		add_pgm_cmt("High page   : %d", high16k_bank);

		char bank_info[32];
		// Add bank comments
		add_extra_cmt(0x8000, 1, "Fixed bank, page 2 mapped");
		qsnprintf(bank_info, 32, "High memory bank, page %i mapped", high16k_bank);
		add_extra_cmt(0xC000, 1, bank_info);
	}
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
loader_t LDSC =
{
	IDP_INTERFACE_VERSION,
	0, // loader flags
	//      check input file format. if recognized, then return 1
	//      and fill 'fileformatname'.
	//      otherwise return 0
	accept_file,
	//
	// load file into the database.
	//
	load_file,
	//
	//	create output file from the database.
	//	this function may be absent.
	//
	NULL,
	//      take care of a moved segment (fix up relocations, for example)
	NULL,
};

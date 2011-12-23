/*
* Copyright 2011 James Koppel
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file excfept in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

/*
 * REProgram enables you to almost-arbitrarily alter areas of an executable
 * when run under the debugger.
 */


#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <expr.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <netnode.hpp>
#include <kernwin.hpp>

#include <stdlib.h>
#include <string.h>

#include <map>
#include <utility>
#include <vector>
#include <set>

using namespace std;

/*
 * According to the Internet, x86 gives an error if an instruction exceeds 15 bytes,
 * though the spec allows them to grow slightly longer
 */
 #define MAX_INSTRUCTION_LENGTH 20 
 #define MAX_INPUT_LENGTH 100000
 #define MAX_DISASM_LENGTH 500000

 #define NOP_BYTE (0x90)

typedef map<ea_t, pair<ea_t, vector<vector<uchar>*>* > > repmap;

repmap replacements;
set<ea_t> disabled_addrs;

set<ea_t> start_bpts;
map<ea_t, ea_t> end_for_start;
map<ea_t, pair<ea_t, int> > midreprgm_bpts;

bgcolor_t disabled_col = 0x00222222;
bgcolor_t overridden_col = 0x0000CC00;

const char* node_name = "$ REProgram addresses";

netnode *prim_node = NULL;

char asm_disasm[MAX_DISASM_LENGTH];

/*
 * These exist since VC7 appears to forbid references to stack variables
 * being passed around
 */
char *next_token = NULL;
char *asmt;

/*
 * Also returns a disassembly
 * of that assembly, to see what it was actually assembled to
 */
int assemble_line(ea_t ea, const char *line, uchar *bin, char* buf=NULL, size_t bufsize=0) {

	int size = ph.notify(processor_t::assemble, ea, 0, ea, true, line, bin);

	for(int i = 0; i < size; i++) {
		patch_byte(ea+i, bin[i]);
	}

	if(buf != NULL) {
		generate_disasm_line(ea, buf, bufsize);
	}

	for(ea_t e = ea; e < ea + size; e++) {
		patch_byte(e, get_original_byte(e));
	}
	
	return size;
}

void place_next_reprogrammed_insns(ea_t start, int first_insn) {
	ea_t end = replacements[start].first;
	vector<vector<uchar>*>* ovec = replacements[start].second;

	ea_t e = start;

	bool fits = true;

	int last_insn = first_insn;


	for(vector<vector<uchar>*>::iterator ovit = ovec->begin() + first_insn;
		ovit != ovec->end();
		ovit++) {
			vector<uchar>* ivec = *ovit;
	
			if(e+ivec->size() > end) {
				fits = false;
				break;
			}

			for(vector<uchar>::iterator ivit = ivec->begin(); ivit != ivec->end(); ivit++) {
				put_dbg_byte(e, *ivit);
				//msg("putting %d at %a\n", *ivit, e);
				e++;
			}

			last_insn++;
		}

	if(fits) {
		for(; e < end; e++) {
			put_dbg_byte(e, NOP_BYTE);
		}

	} else {
		midreprgm_bpts[e] = make_pair(start, last_insn); 
		end_for_start[start] = e;

		bool r1 = request_add_bpt(e);
	}

	invalidate_dbgmem_contents(BADADDR, 0);

}

//--------------------------------------------------------------------------
static int idaapi dbg_callback(void * /*user_data*/, int notification_code, va_list va)
{
	if(notification_code == dbg_process_start) {

		start_bpts.clear();
		end_for_start.clear();
		midreprgm_bpts.clear();
		
		repmap::iterator it;

		for(it = replacements.begin(); it != replacements.end(); it++) {
			ea_t start = it->first;
			ea_t end = it->second.first;
			vector<vector<uchar>*>* ovec = it->second.second;

			ea_t e = start;

			bool fits = true;

			for(vector<vector<uchar>*>::iterator ovit = ovec->begin(); ovit != ovec->end(); ovit++) {
				vector<uchar>* ivec = *ovit;

				if(e+ivec->size() > end) {
					fits = false;
					break;
				}

				for(vector<uchar>::iterator ivit = ivec->begin(); ivit != ivec->end(); ivit++) {
					put_dbg_byte(e, *ivit);
					//msg("putting %d at %a\n", *ivit, e);
					e++;
				}
			}

			if(fits) {
				for(; e < end; e++) {
					put_dbg_byte(e, NOP_BYTE);
				}
			} else {
				start_bpts.insert(start);
				request_add_bpt(start);
			}

			run_requests();

		}
	} else if(notification_code == dbg_bpt) {
		thid_t tid = va_arg(va, thid_t);
		ea_t addr  = va_arg(va, ea_t);

		if(start_bpts.count(addr) > 0) {

			if(end_for_start.count(addr) > 0) {
				if(exist_bpt(addr))
					request_del_bpt(end_for_start[addr]);
				end_for_start.erase(end_for_start.find(addr));
			}

			place_next_reprogrammed_insns(addr, 0);
			bool r1 = request_continue_process();
		} else if(midreprgm_bpts.count(addr) > 0) {
			request_del_bpt(addr);


			ea_t start = midreprgm_bpts[addr].first;
			int next_insn = midreprgm_bpts[addr].second;
			midreprgm_bpts.erase(midreprgm_bpts.find(addr));
			
			if(end_for_start.count(start) > 0) {
				end_for_start.erase(end_for_start.find(start));
			}

			place_next_reprogrammed_insns(start, next_insn);
			
			regval_t v;
			v.rvtype = RVT_INT;
			v.ival = start;
			bool r1 = request_set_reg_val("EIP", &v);
			bool r2 = request_continue_process();
		}
		run_requests();
	} else if(notification_code == dbg_process_exit) {
		for(set<ea_t>::iterator it = start_bpts.begin(); it != start_bpts.end(); it++) {
			request_del_bpt(*it);
			if(end_for_start.count(*it) > 0) {
				end_for_start.erase(end_for_start.find(*it));
			}
		}
		run_requests();
	}

	return 0;
}

static int idaapi idp_callback(void * /*user_data*/, int notification_code, va_list va) {
	
	if(notification_code == processor_t::get_bg_color) { 
		ea_t addr = va_arg(va, ea_t);
		bgcolor_t *col  = va_arg(va, bgcolor_t*);

		if(disabled_addrs.count(addr)) {
			if(replacements.count(addr)) {
				*col = overridden_col;
			} else {
				*col = disabled_col;
			}

			return 2;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

ea_t find_reprogrammed_head(ea_t mid) {
	
	ea_t e;

	for(e = mid; replacements.count(e) == 0; e--);

	return e;
}

void revert_segment(ea_t start) {

	ea_t end = replacements[start].first;

	for(vector<vector<uchar>*>::iterator it = replacements[start].second->begin();
		it != replacements[start].second->end();
		it++) {
		
			delete *it;
	}

	delete replacements[start].second;

	replacements.erase(replacements.find(start));

	disabled_addrs.erase(disabled_addrs.find(start), disabled_addrs.find(end));

	set_manual_insn(start, "");

	netnode repnode(prim_node->altval(start));
	repnode.kill();
	prim_node->altdel(start);
}

void reprogram_segment(ea_t start, ea_t end) {
	
	asmt = asktext(MAX_INPUT_LENGTH, NULL, "", "Asm: ");

	if(asmt == NULL) {
		return;
	}

	for(ea_t e = start; e < end; e++) {
		disabled_addrs.insert(e);
	}

	memset(asm_disasm, '\0', sizeof(asm_disasm));
	char* line_disasm_buf = (char*)calloc(MAXSTR, sizeof(char)); 

	vector<vector<uchar>*>* vec = new vector<vector<uchar>*>;
	netnode repnode;
	repnode.create();

	bool succ = true;
	bool asm_error = false;

	nodeidx_t idx = 0;

	for(char *tok = strtok_s(asmt, "\n", &next_token);
		tok != NULL;
		tok = strtok_s(NULL, "\n", &next_token)) {
		
			
			uchar *assembled_buf = (uchar*)calloc(MAX_INSTRUCTION_LENGTH, sizeof(uchar));
			int size = assemble_line(start, tok, assembled_buf, line_disasm_buf, MAXSTR);

			//Potential Schlemiel-the-painter algorithm, depending on implementation of qstrncat
			qstrncat(asm_disasm, line_disasm_buf, MAX_DISASM_LENGTH);
			qstrncat(asm_disasm, "\n", MAX_DISASM_LENGTH);

			if(size <= 0) {
				succ = false;
				asm_error = true;
			}

			if((unsigned int)size > end - start) {
				succ = false;
			}

			repnode.altset(idx, size);
			idx++;

			vector<uchar>* v = new vector<uchar>;
			for(int i = 0; i < size; i++) {
				v->push_back(assembled_buf[i]);
				repnode.altset(idx, assembled_buf[i]);
				idx++;
			}
			
			free(assembled_buf);

			vec->push_back(v);
	}

	free(line_disasm_buf);
	
	set_manual_insn(start, asm_disasm);

	replacements[start] = make_pair(end, vec);


	repnode.hashset("length", vec->size());
	repnode.hashset("end", end);
	prim_node->altset(start, (nodeidx_t)repnode);

	if(!succ) {
		if(!asm_error) {
			info("The selection cannot be reprogrammed with the provided assembly "
					"because one of the instructions is larger than the entire selection.");
		}
		revert_segment(start);
	}
}


void handle_segment(ea_t start, ea_t end) {

	bool any_enabled = false;

	for(ea_t ea = start; ea < end; ea = next_not_tail(ea)) {
		if(disabled_addrs.count(ea)) {
			revert_segment(find_reprogrammed_head(ea));
			any_enabled = true;
		}
	}

	if(any_enabled) {
		return;
	}

	reprogram_segment(start, end);
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
	ea_t start, end;
	ea_t scr = get_screen_ea();

	if(read_selection(&start, &end)) {
		handle_segment(start, end);
	} else if(scr != BADADDR) {
		handle_segment(scr, next_not_tail(scr));
	}
}

static uint32 idaapi view_rep_sizer(void* obj) {
	repmap* m = (repmap*)obj;

	return m->size();
}

static char* idaapi view_rep_getline(void *obj, uint32 n, char* buf) {
	if(n==0) {
		qstrncpy(buf, "Address", strlen("Address")+1);
	} else {
		repmap* m = (repmap*)obj;

		repmap::iterator it;
		uint32 i;
		for(i = 0, it = m->begin(); i < n-1; it++, i++);

		qsnprintf(buf, 16, "0x%a", it->first);
	}

	return buf;
}

static bool idaapi view_reprogrammed(void* /* udata */) {
	int choice = choose((void*)&replacements, 16, view_rep_sizer, view_rep_getline, "Reprogrammed areas");

	if(choice <= 0) {
		return true;;
	}
	
	repmap::iterator it;
	int i;
	for(i = 0, it = replacements.begin(); i < choice-1; it++, i++);

	ea_t dest = it->first;
	jumpto(dest);

	return true;
}

//--------------------------------------------------------------------------
int idaapi init(void) {

	if(!hook_to_notification_point(HT_DBG, dbg_callback, NULL)) {
		msg("REProgram failed to hook to debugger; plugin not loaded.\n");
		return PLUGIN_SKIP;
	}

	if(!hook_to_notification_point(HT_IDP, idp_callback, NULL)) {
		unhook_from_notification_point(HT_DBG, dbg_callback, NULL);
		msg("REProgram failed to hook to IDA events; plugin not loaded.\n");
		return PLUGIN_SKIP;
	}

	if(!add_menu_item("View/RecentScripts","Reprogrammed areas", NULL, SETMENU_APP, view_reprogrammed, NULL)) {
		msg("REProgram failed to add its viewer menu item; plugin not loaded\n");
		return PLUGIN_SKIP;
	}

	prim_node = new netnode(node_name, 0, true);


	for(nodeidx_t idx = prim_node->alt1st(); idx != BADNODE; idx = prim_node->altnxt(idx)) {
		nodeidx_t id = prim_node->altval(idx);
		netnode* repnode = new netnode(id);

		int len;
		repnode->hashval("length", &len, sizeof(int));

		ea_t end;
		repnode->hashval("end", &end, sizeof(ea_t));


		nodeidx_t idx2 = repnode->alt1st();

		vector<vector<uchar>*>* vec = new vector<vector<uchar>*>;

		for(int i = 0; i < len; i++) {
			vector<uchar>* line = new vector<uchar>;

			uint32 linelen = repnode->altval(idx2);
			idx2 = repnode->altnxt(idx2);

			for(uint32 j = 0; j < linelen; j++) {
				line->push_back(repnode->altval(idx2));
				idx2 = repnode->altnxt(idx2);
			}

			vec->push_back(line);
		}

		replacements[idx] = make_pair(end, vec);

		for(ea_t e = idx; e < end; e++) {
			disabled_addrs.insert(e);
		}

		delete repnode;
	}


	return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
	unhook_from_notification_point(HT_DBG, dbg_callback, NULL);
	unhook_from_notification_point(HT_IDP, idp_callback, NULL);
	replacements.clear();
	start_bpts.clear();
	end_for_start.clear();
	midreprgm_bpts.clear();
}

//--------------------------------------------------------------------------
char wanted_name[] = "Reprogram selection";
char wanted_hotkey[] = "Alt+F2";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_DRAW | PLUGIN_PROC, // plugin flags
	init,                 // initialize

	term,                 // terminate. this pointer may be NULL.

	run,                  // invoke plugin

	wanted_name,          // long comment about the plugin
	// it could appear in the status line
	// or as a hint

	wanted_name,          // multiline help about the plugin

	wanted_name,          // the preferred short name of the plugin
	wanted_hotkey         // the preferred hotkey to run the plugin
};

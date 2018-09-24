# Copyright (C) 2009 Anton Blanchard <anton@au.ibm.com>, IBM
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version
# 2 of the License, or (at your option) any later version.

import struct
import re
import dtl


class timebase(object):
	frequency = 0

	def __init__(self, cpuinfo_file='/proc/cpuinfo'):
		f = open(cpuinfo_file, 'r')

		ppc = re.compile('timebase\s*:\s*(\d+)')
		x86 = re.compile('cpu MHz\s*:\s*([\d.]+)')
		freq = None
		for line in f.readlines():
			g = ppc.match(line)
			if g:
				freq = int(g.group(1))

			g = x86.match(line)
			if g:
				freq = float(g.group(1))
				freq *= 1000000

		f.close()

		if freq == None:
			print "WARNING: Unable to get timebase frequency, " \
				"hardwiring to 512000000"
			freq = 512000000

		self.frequency = freq

	def to_us(self, tb):
		return tb * 1000000.0 / self.frequency

	def to_ms(self, tb):
		return tb * 1000.0 / self.frequency


class kallsyms(object):
	syms = {}

	def __init__(self, kallsyms_file='/proc/kallsyms'):
		f = open(kallsyms_file, 'r')

		# We match on the bottom 32bits which allows
		# our kernel records to be smaller
		for line in f.readlines():
			array = line.split()
			addr = int(array[0], 16) & 0xffffffff
			symbol = array[2]
			self.syms[addr] = symbol

		self.syms[0] = 'unknown'

		f.close()

	def lookup(self, addr):
		try:
			return self.syms[addr]
		except:
			return '0x%x' % addr

	def lookup_name(self, name):
		for k, v in self.syms.iteritems():
			if v == name:
				return k

		return 'unknown'


class interrupts(object):
	irqs = {}

	def __init__(self, interrupts_file='/proc/interrupts'):
		f = open(interrupts_file, 'r')

		r = re.compile('\s*\d+:')
		for line in f.readlines():
			if r.match(line):
				array = line.split()
				irq = int(array[0].replace(':', ''))
				name = array[-1]
				self.irqs[irq] = name

		f.close()

	def lookup(self, irq):
		try:
			return self.irqs[irq]
		except:
			return ''


class softirqs(object):
	softirq_reasons = [
		'HI_SOFTIRQ',
		'TIMER_SOFTIRQ',
		'NET_TX_SOFTIRQ',
		'NET_RX_SOFTIRQ',
		'BLOCK_SOFTIRQ',
		'BLOCK_IOPOLL_SOFTIRQ',
		'TASKLET_SOFTIRQ',
		'SCHED_SOFTIRQ',
		'HRTIMER_SOFTIRQ',
		'RCU_SOFTIRQ',
	]

	def lookup(self, pending):
		return self.softirq_reasons[pending]


class hcalls(object):
	hcall_names = {}
	hcall_names[0x04] = "H_REMOVE"
	hcall_names[0x08] = "H_ENTER"
	hcall_names[0x0c] = "H_READ"
	hcall_names[0x10] = "H_CLEAR_MOD"
	hcall_names[0x14] = "H_CLEAR_REF"
	hcall_names[0x18] = "H_PROTECT"
	hcall_names[0x1c] = "H_GET_TCE"
	hcall_names[0x20] = "H_PUT_TCE"
	hcall_names[0x24] = "H_SET_SPRG0"
	hcall_names[0x28] = "H_SET_DABR"
	hcall_names[0x2c] = "H_PAGE_INIT"
	hcall_names[0x30] = "H_SET_ASR"
	hcall_names[0x34] = "H_ASR_ON"
	hcall_names[0x38] = "H_ASR_OFF"
	hcall_names[0x3c] = "H_LOGICAL_CI_LOAD"
	hcall_names[0x40] = "H_LOGICAL_CI_STORE"
	hcall_names[0x44] = "H_LOGICAL_CACHE_LOAD"
	hcall_names[0x48] = "H_LOGICAL_CACHE_STORE"
	hcall_names[0x4c] = "H_LOGICAL_ICBI"
	hcall_names[0x50] = "H_LOGICAL_DCBF"
	hcall_names[0x54] = "H_GET_TERM_CHAR"
	hcall_names[0x58] = "H_PUT_TERM_CHAR"
	hcall_names[0x5c] = "H_REAL_TO_LOGICAL"
	hcall_names[0x60] = "H_HYPERVISOR_DATA"
	hcall_names[0x64] = "H_EOI"
	hcall_names[0x68] = "H_CPPR"
	hcall_names[0x6c] = "H_IPI"
	hcall_names[0x70] = "H_IPOLL"
	hcall_names[0x74] = "H_XIRR"
	hcall_names[0x7c] = "H_PERFMON"
	hcall_names[0x78] = "H_MIGRATE_DMA"
	hcall_names[0xDC] = "H_REGISTER_VPA"
	hcall_names[0xE0] = "H_CEDE"
	hcall_names[0xE4] = "H_CONFER"
	hcall_names[0xE8] = "H_PROD"
	hcall_names[0xEC] = "H_GET_PPP"
	hcall_names[0xF0] = "H_SET_PPP"
	hcall_names[0xF4] = "H_PURR"
	hcall_names[0xF8] = "H_PIC"
	hcall_names[0xFC] = "H_REG_CRQ"
	hcall_names[0x100] = "H_FREE_CRQ"
	hcall_names[0x104] = "H_VIO_SIGNAL"
	hcall_names[0x108] = "H_SEND_CRQ"
	hcall_names[0x110] = "H_COPY_RDMA"
	hcall_names[0x114] = "H_REGISTER_LOGICAL_LAN"
	hcall_names[0x118] = "H_FREE_LOGICAL_LAN"
	hcall_names[0x11C] = "H_ADD_LOGICAL_LAN_BUFFER"
	hcall_names[0x120] = "H_SEND_LOGICAL_LAN"
	hcall_names[0x124] = "H_BULK_REMOVE"
	hcall_names[0x130] = "H_MULTICAST_CTRL"
	hcall_names[0x134] = "H_SET_XDABR"
	hcall_names[0x138] = "H_STUFF_TCE"
	hcall_names[0x13C] = "H_PUT_TCE_INDIRECT"
	hcall_names[0x14C] = "H_CHANGE_LOGICAL_LAN_MAC"
	hcall_names[0x150] = "H_VTERM_PARTNER_INFO"
	hcall_names[0x154] = "H_REGISTER_VTERM"
	hcall_names[0x158] = "H_FREE_VTERM"
	hcall_names[0x15C] = "H_RESET_EVENTS"
	hcall_names[0x160] = "H_ALLOC_RESOURCE"
	hcall_names[0x164] = "H_FREE_RESOURCE"
	hcall_names[0x168] = "H_MODIFY_QP"
	hcall_names[0x16C] = "H_QUERY_QP"
	hcall_names[0x170] = "H_REREGISTER_PMR"
	hcall_names[0x174] = "H_REGISTER_SMR"
	hcall_names[0x178] = "H_QUERY_MR"
	hcall_names[0x17C] = "H_QUERY_MW"
	hcall_names[0x180] = "H_QUERY_HCA"
	hcall_names[0x184] = "H_QUERY_PORT"
	hcall_names[0x188] = "H_MODIFY_PORT"
	hcall_names[0x18C] = "H_DEFINE_AQP1"
	hcall_names[0x190] = "H_GET_TRACE_BUFFER"
	hcall_names[0x194] = "H_DEFINE_AQP0"
	hcall_names[0x198] = "H_RESIZE_MR"
	hcall_names[0x19C] = "H_ATTACH_MCQP"
	hcall_names[0x1A0] = "H_DETACH_MCQP"
	hcall_names[0x1A4] = "H_CREATE_RPT"
	hcall_names[0x1A8] = "H_REMOVE_RPT"
	hcall_names[0x1AC] = "H_REGISTER_RPAGES"
	hcall_names[0x1B0] = "H_DISABLE_AND_GETC"
	hcall_names[0x1B4] = "H_ERROR_DATA"
	hcall_names[0x1B8] = "H_GET_HCA_INFO"
	hcall_names[0x1BC] = "H_GET_PERF_COUNT"
	hcall_names[0x1C0] = "H_MANAGE_TRACE"
	hcall_names[0x1C8] = "H_GET_CPU_CHARACTERISTICS"
	hcall_names[0x1D4] = "H_FREE_LOGICAL_LAN_BUFFER"
	hcall_names[0x1E4] = "H_QUERY_INT_STATE"
	hcall_names[0x1D8] = "H_POLL_PENDING"
	hcall_names[0x244] = "H_ILLAN_ATTRIBUTES"
	hcall_names[0x250] = "H_MODIFY_HEA_QP"
	hcall_names[0x254] = "H_QUERY_HEA_QP"
	hcall_names[0x258] = "H_QUERY_HEA"
	hcall_names[0x25C] = "H_QUERY_HEA_PORT"
	hcall_names[0x260] = "H_MODIFY_HEA_PORT"
	hcall_names[0x264] = "H_REG_BCMC"
	hcall_names[0x268] = "H_DEREG_BCMC"
	hcall_names[0x26C] = "H_REGISTER_HEA_RPAGES"
	hcall_names[0x270] = "H_DISABLE_AND_GET_HEA"
	hcall_names[0x274] = "H_GET_HEA_INFO"
	hcall_names[0x278] = "H_ALLOC_HEA_RESOURCE"
	hcall_names[0x284] = "H_ADD_CONN"
	hcall_names[0x288] = "H_DEL_CONN"
	hcall_names[0x298] = "H_JOIN"
	hcall_names[0x2A4] = "H_VASI_STATE"
	hcall_names[0x2A8] = "H_VIOCTL"
	hcall_names[0x2B0] = "H_ENABLE_CRQ"
	hcall_names[0x2B8] = "H_GET_EM_PARMS"
	hcall_names[0x2D0] = "H_SET_MPP"
	hcall_names[0x2D4] = "H_GET_MPP"
	hcall_names[0x2DC] = "H_REG_SUB_CRQ"
	hcall_names[0x2EC] = "H_HOME_NODE_ASSOCIATIVITY"
	hcall_names[0x2E0] = "H_FREE_SUB_CRQ"
	hcall_names[0x2E4] = "H_SEND_SUB_CRQ"
	hcall_names[0x2E8] = "H_SEND_SUB_CRQ_INDIRECT"
	hcall_names[0x2F4] = "H_BEST_ENERGY"
	hcall_names[0x2FC] = "H_XIRR_X"
	hcall_names[0x300] = "H_RANDOM"
	hcall_names[0x304] = "H_COP"
	hcall_names[0x314] = "H_GET_MPP_X"
	hcall_names[0x31C] = "H_SET_MODE"
	hcall_names[0x358] = "H_CLEAR_HPT"
	hcall_names[0x360] = "H_REQUEST_VMC"
	hcall_names[0x36C] = "H_RESIZE_HPT_PREPARE"
	hcall_names[0x370] = "H_RESIZE_HPT_COMMIT"
	hcall_names[0x37C] = "H_REGISTER_PROC_TBL"
	hcall_names[0x380] = "H_SIGNAL_SYS_RESET"
	hcall_names[0x3A8] = "H_INT_GET_SOURCE_INFO"
	hcall_names[0x3AC] = "H_INT_SET_SOURCE_CONFIG"
	hcall_names[0x3B0] = "H_INT_GET_SOURCE_CONFIG"
	hcall_names[0x3B4] = "H_INT_GET_QUEUE_INFO"
	hcall_names[0x3B8] = "H_INT_SET_QUEUE_CONFIG"
	hcall_names[0x3BC] = "H_INT_GET_QUEUE_CONFIG"
	hcall_names[0x3C0] = "H_INT_SET_OS_REPORTING_LINE"
	hcall_names[0x3C4] = "H_INT_GET_OS_REPORTING_LINE"
	hcall_names[0x3C8] = "H_INT_ESB"
	hcall_names[0x3CC] = "H_INT_SYNC"
	hcall_names[0x3D0] = "H_INT_RESET"

	def lookup(self, opcode):
		if opcode in self.hcall_names:
			return self.hcall_names[opcode]
		else:
			return "%d" % opcode


class opal_calls(object):
	opal_names = {}
	opal_names[0] = "OPAL_TEST"
	opal_names[1] = "OPAL_CONSOLE_WRITE"
	opal_names[2] = "OPAL_CONSOLE_READ"
	opal_names[3] = "OPAL_RTC_READ"
	opal_names[4] = "OPAL_RTC_WRITE"
	opal_names[5] = "OPAL_CEC_POWER_DOWN"
	opal_names[6] = "OPAL_CEC_REBOOT"
	opal_names[7] = "OPAL_READ_NVRAM"
	opal_names[8] = "OPAL_WRITE_NVRAM"
	opal_names[9] = "OPAL_HANDLE_INTERRUPT"
	opal_names[10] = "OPAL_POLL_EVENTS"
	opal_names[11] = "OPAL_PCI_SET_HUB_TCE_MEMORY"
	opal_names[12] = "OPAL_PCI_SET_PHB_TCE_MEMORY"
	opal_names[13] = "OPAL_PCI_CONFIG_READ_BYTE"
	opal_names[14] = "OPAL_PCI_CONFIG_READ_HALF_WORD"
	opal_names[15] = "OPAL_PCI_CONFIG_READ_WORD"
	opal_names[16] = "OPAL_PCI_CONFIG_WRITE_BYTE"
	opal_names[17] = "OPAL_PCI_CONFIG_WRITE_HALF_WORD"
	opal_names[18] = "OPAL_PCI_CONFIG_WRITE_WORD"
	opal_names[19] = "OPAL_SET_XIVE"
	opal_names[20] = "OPAL_GET_XIVE"
	opal_names[21] = "OPAL_GET_COMPLETION_TOKEN_STATUS"
	opal_names[22] = "OPAL_REGISTER_OPAL_EXCEPTION_HANDLER"
	opal_names[23] = "OPAL_PCI_EEH_FREEZE_STATUS"
	opal_names[24] = "OPAL_PCI_SHPC"
	opal_names[25] = "OPAL_CONSOLE_WRITE_BUFFER_SPACE"
	opal_names[26] = "OPAL_PCI_EEH_FREEZE_CLEAR"
	opal_names[27] = "OPAL_PCI_PHB_MMIO_ENABLE"
	opal_names[28] = "OPAL_PCI_SET_PHB_MEM_WINDOW"
	opal_names[29] = "OPAL_PCI_MAP_PE_MMIO_WINDOW"
	opal_names[30] = "OPAL_PCI_SET_PHB_TABLE_MEMORY"
	opal_names[31] = "OPAL_PCI_SET_PE"
	opal_names[32] = "OPAL_PCI_SET_PELTV"
	opal_names[33] = "OPAL_PCI_SET_MVE"
	opal_names[34] = "OPAL_PCI_SET_MVE_ENABLE"
	opal_names[35] = "OPAL_PCI_GET_XIVE_REISSUE"
	opal_names[36] = "OPAL_PCI_SET_XIVE_REISSUE"
	opal_names[37] = "OPAL_PCI_SET_XIVE_PE"
	opal_names[38] = "OPAL_GET_XIVE_SOURCE"
	opal_names[39] = "OPAL_GET_MSI_32"
	opal_names[40] = "OPAL_GET_MSI_64"
	opal_names[41] = "OPAL_START_CPU"
	opal_names[42] = "OPAL_QUERY_CPU_STATUS"
	opal_names[43] = "OPAL_WRITE_OPPANEL"
	opal_names[44] = "OPAL_PCI_MAP_PE_DMA_WINDOW"
	opal_names[45] = "OPAL_PCI_MAP_PE_DMA_WINDOW_REAL"
	opal_names[49] = "OPAL_PCI_RESET"
	opal_names[50] = "OPAL_PCI_GET_HUB_DIAG_DATA"
	opal_names[51] = "OPAL_PCI_GET_PHB_DIAG_DATA"
	opal_names[52] = "OPAL_PCI_FENCE_PHB"
	opal_names[53] = "OPAL_PCI_REINIT"
	opal_names[54] = "OPAL_PCI_MASK_PE_ERROR"
	opal_names[55] = "OPAL_SET_SLOT_LED_STATUS"
	opal_names[56] = "OPAL_GET_EPOW_STATUS"
	opal_names[57] = "OPAL_SET_SYSTEM_ATTENTION_LED"
	opal_names[58] = "OPAL_RESERVED1"
	opal_names[59] = "OPAL_RESERVED2"
	opal_names[60] = "OPAL_PCI_NEXT_ERROR"
	opal_names[61] = "OPAL_PCI_EEH_FREEZE_STATUS2"
	opal_names[62] = "OPAL_PCI_POLL"
	opal_names[63] = "OPAL_PCI_MSI_EOI"
	opal_names[64] = "OPAL_PCI_GET_PHB_DIAG_DATA2"
	opal_names[65] = "OPAL_XSCOM_READ"
	opal_names[66] = "OPAL_XSCOM_WRITE"
	opal_names[67] = "OPAL_LPC_READ"
	opal_names[68] = "OPAL_LPC_WRITE"
	opal_names[69] = "OPAL_RETURN_CPU"
	opal_names[70] = "OPAL_REINIT_CPUS"
	opal_names[71] = "OPAL_ELOG_READ"
	opal_names[72] = "OPAL_ELOG_WRITE"
	opal_names[73] = "OPAL_ELOG_ACK"
	opal_names[74] = "OPAL_ELOG_RESEND"
	opal_names[75] = "OPAL_ELOG_SIZE"
	opal_names[76] = "OPAL_FLASH_VALIDATE"
	opal_names[77] = "OPAL_FLASH_MANAGE"
	opal_names[78] = "OPAL_FLASH_UPDATE"
	opal_names[79] = "OPAL_RESYNC_TIMEBASE"
	opal_names[80] = "OPAL_CHECK_TOKEN"
	opal_names[81] = "OPAL_DUMP_INIT"
	opal_names[82] = "OPAL_DUMP_INFO"
	opal_names[83] = "OPAL_DUMP_READ"
	opal_names[84] = "OPAL_DUMP_ACK"
	opal_names[85] = "OPAL_GET_MSG"
	opal_names[86] = "OPAL_CHECK_ASYNC_COMPLETION"
	opal_names[87] = "OPAL_SYNC_HOST_REBOOT"
	opal_names[88] = "OPAL_SENSOR_READ"
	opal_names[89] = "OPAL_GET_PARAM"
	opal_names[90] = "OPAL_SET_PARAM"
	opal_names[91] = "OPAL_DUMP_RESEND"
	opal_names[92] = "OPAL_ELOG_SEND"
	opal_names[93] = "OPAL_PCI_SET_PHB_CAPI_MODE"
	opal_names[94] = "OPAL_DUMP_INFO2"
	opal_names[95] = "OPAL_WRITE_OPPANEL_ASYNC"
	opal_names[96] = "OPAL_PCI_ERR_INJECT"
	opal_names[97] = "OPAL_PCI_EEH_FREEZE_SET"
	opal_names[98] = "OPAL_HANDLE_HMI"
	opal_names[99] = "OPAL_CONFIG_CPU_IDLE_STATE"
	opal_names[100] = "OPAL_SLW_SET_REG"
	opal_names[101] = "OPAL_REGISTER_DUMP_REGION"
	opal_names[102] = "OPAL_UNREGISTER_DUMP_REGION"
	opal_names[103] = "OPAL_WRITE_TPO"
	opal_names[104] = "OPAL_READ_TPO"
	opal_names[105] = "OPAL_GET_DPO_STATUS"
	opal_names[106] = "OPAL_OLD_I2C_REQUEST"
	opal_names[107] = "OPAL_IPMI_SEND"
	opal_names[108] = "OPAL_IPMI_RECV"
	opal_names[109] = "OPAL_I2C_REQUEST"
	opal_names[110] = "OPAL_FLASH_READ"
	opal_names[111] = "OPAL_FLASH_WRITE"
	opal_names[112] = "OPAL_FLASH_ERASE"
	opal_names[113] = "OPAL_PRD_MSG"
	opal_names[114] = "OPAL_LEDS_GET_INDICATOR"
	opal_names[115] = "OPAL_LEDS_SET_INDICATOR"
	opal_names[116] = "OPAL_CEC_REBOOT2"
	opal_names[117] = "OPAL_CONSOLE_FLUSH"
	opal_names[118] = "OPAL_GET_DEVICE_TREE"
	opal_names[119] = "OPAL_PCI_GET_PRESENCE_STATE"
	opal_names[120] = "OPAL_PCI_GET_POWER_STATE"
	opal_names[121] = "OPAL_PCI_SET_POWER_STATE"
	opal_names[122] = "OPAL_INT_GET_XIRR"
	opal_names[123] = "OPAL_INT_SET_CPPR"
	opal_names[124] = "OPAL_INT_EOI"
	opal_names[125] = "OPAL_INT_SET_MFRR"
	opal_names[126] = "OPAL_PCI_TCE_KILL"
	opal_names[127] = "OPAL_NMMU_SET_PTCR"
	opal_names[128] = "OPAL_XIVE_RESET"
	opal_names[129] = "OPAL_XIVE_GET_IRQ_INFO"
	opal_names[130] = "OPAL_XIVE_GET_IRQ_CONFIG"
	opal_names[131] = "OPAL_XIVE_SET_IRQ_CONFIG"
	opal_names[132] = "OPAL_XIVE_GET_QUEUE_INFO"
	opal_names[133] = "OPAL_XIVE_SET_QUEUE_INFO"
	opal_names[134] = "OPAL_XIVE_DONATE_PAGE"
	opal_names[135] = "OPAL_XIVE_ALLOCATE_VP_BLOCK"
	opal_names[136] = "OPAL_XIVE_FREE_VP_BLOCK"
	opal_names[137] = "OPAL_XIVE_GET_VP_INFO"
	opal_names[138] = "OPAL_XIVE_SET_VP_INFO"
	opal_names[139] = "OPAL_XIVE_ALLOCATE_IRQ"
	opal_names[140] = "OPAL_XIVE_FREE_IRQ"
	opal_names[141] = "OPAL_XIVE_SYNC"
	opal_names[142] = "OPAL_XIVE_DUMP"
	opal_names[143] = "OPAL_XIVE_RESERVED3"
	opal_names[144] = "OPAL_XIVE_RESERVED4"
	opal_names[145] = "OPAL_SIGNAL_SYSTEM_RESET"
	opal_names[146] = "OPAL_NPU_INIT_CONTEXT"
	opal_names[147] = "OPAL_NPU_DESTROY_CONTEXT"
	opal_names[148] = "OPAL_NPU_MAP_LPAR"
	opal_names[149] = "OPAL_IMC_COUNTERS_INIT"
	opal_names[150] = "OPAL_IMC_COUNTERS_START"
	opal_names[151] = "OPAL_IMC_COUNTERS_STOP"
	opal_names[152] = "OPAL_GET_POWERCAP"
	opal_names[153] = "OPAL_SET_POWERCAP"
	opal_names[154] = "OPAL_GET_POWER_SHIFT_RATIO"
	opal_names[155] = "OPAL_SET_POWER_SHIFT_RATIO"
	opal_names[156] = "OPAL_SENSOR_GROUP_CLEAR"
	opal_names[157] = "OPAL_PCI_SET_P2P"
	opal_names[158] = "OPAL_QUIESCE"
	opal_names[159] = "OPAL_NPU_SPA_SETUP"
	opal_names[160] = "OPAL_NPU_SPA_CLEAR_CACHE"
	opal_names[161] = "OPAL_NPU_TL_SET"
	opal_names[162] = "OPAL_SENSOR_READ_U64"
	opal_names[163] = "OPAL_SENSOR_GROUP_ENABLE"
	opal_names[164] = "OPAL_PCI_GET_PBCQ_TUNNEL_BAR"
	opal_names[165] = "OPAL_PCI_SET_PBCQ_TUNNEL_BAR"
	opal_names[167] = "OPAL_NX_COPROC_INIT"

	def lookup(self, opcode):
		if opcode in self.opal_names:
			return self.opal_names[opcode]
		else:
			return "%d" % opcode


class eventtype:
	CONTEXT_SWITCH		= 1
	LOST_SAMPLES		= 2
	INTERRUPT_ENTRY		= 10
	INTERRUPT_EXIT		= 11
	INTERRUPT_HANDLER_ENTRY	= 12
	INTERRUPT_HANDLER_EXIT	= 13
	TIMER_INTERRUPT_ENTRY	= 14
	TIMER_INTERRUPT_EXIT	= 15
	TIMER_ENTRY		= 16
	TIMER_EXIT		= 17
	SOFTIRQ_ENTRY		= 18
	SOFTIRQ_EXIT		= 19
	WORKQUEUE_ENTRY		= 20
	WORKQUEUE_EXIT		= 21
	TASKLET_ENTRY		= 22
	TASKLET_EXIT		= 23
	HCALL_ENTRY		= 24
	HCALL_EXIT		= 25
	OPAL_ENTRY		= 26
	OPAL_EXIT		= 27
	PHYP_ENTRY		= 100
	PHYP_EXIT		= 101


class entry(object):
	format = '>Q L H H'
	format_comm = '>16s'
	basesize = struct.calcsize(format)
	commsize = struct.calcsize(format_comm)

	def parse(self, buf, start):
		end = start+self.basesize
		(self.tb,
		self.data,
		self.cpu,
		self.event) = struct.unpack(self.format, buf[start:end])
		length = self.basesize

		if self.event == eventtype.CONTEXT_SWITCH:
			start = end
			end = start + self.commsize
			(self.comm,) = struct.unpack(self.format_comm,
						buf[start:end])
			self.comm = self.comm.rstrip('\0')
			# Most people know it as idle, so call it that
			if "swapper" in self.comm:
				self.comm = "idle"
			length += self.commsize

		return length


class eventsource(object):
	def __init__(self, id, name, type):
		self.active = []
		self.inactive = []
		self.id = id
		self.name = name
		self.nametb = 0
		self.type = type

		self._interruptions = []
		self._start = None
		self._last = None

	def start(self, tb):
		if self._last != None:
			delta = tb - self._last
			self.inactive.append(delta)
		self._start = tb
		self._last = tb

	def interrupt(self, tb, duration):
		self._interruptions.append((tb, duration))

	def stop(self, tb):
		tb_orig = tb
		while self._interruptions:
			(i_tb, i_duration) = self._interruptions.pop()
			delta = tb - i_tb
			# Nested interrupts can result in negative deltas,
			# Ignore them until we fix it properly
			if delta >= 0:
				self.active.append(delta)
				tb = i_tb - i_duration

		self._interruptions = []

		total_duration = 0
		if self._start != None:
			delta = tb - self._start
			# Nested interrupts can result in negative deltas,
			# Ignore them until we fix it properly
			if delta >= 0:
				self.active.append(delta)
				total_duration = tb_orig - self._start

		self._start = None

		return total_duration

	def cancel(self):
		self._interruptions = []
		self._start = None
		self._last = None


class stats(object):
	def reset(self):
		for k, v in self.items.iteritems():
			v.cancel()
		self.eventstack = []
		self.firstswitch = True
		self.prevtb = -1
		self.warned = False

	def __init__(self, cumulative=False, interruptions=True,
			procdir='/proc'):
		self.tb = timebase(cpuinfo_file = procdir + '/cpuinfo')
		self.ksyms = kallsyms(kallsyms_file = procdir + '/kallsyms')
		self.i = interrupts(interrupts_file = procdir + '/interrupts')
		self.softirq = softirqs()
		self.hcall = hcalls()
		self.opal = opal_calls()

		self.items = {}
		self.eventstack = []
		self.firstswitch = True
		self.cumulative = cumulative
		self.interruptions = interruptions

		self.reset()

	def _event_start(self, tb, type, key):
		self.items[key].start(tb)
		self.eventstack.append(self.items[key])
		#print "S: %d %d %d" % (type, len(self.eventstack), tb)

	def _event_end(self, tb, type, warn=1):
		if len(self.eventstack) == 0 or \
		    self.eventstack[-1].type != type:
			if warn == True:
				print "WARNING: missing %d start at %d" % (
					type, tb)
		else:
			prev = self.eventstack.pop()
			duration = prev.stop(tb)
			if self.cumulative:
				duration = 0
			if len(self.eventstack) > 0 and self.interruptions:
				self.eventstack[-1].interrupt(tb, duration)
			#print "E: %d %d %d" % (type, len(self.eventstack), tb)

	def sample(self, entry):

		if entry.tb < self.prevtb:
			if self.warned == False:
				self.warned = True
				print 'WARNING: time went backwards at %d' % (
					self.prevtb)
			return

		self.prevtb = entry.tb

		if entry.event == eventtype.CONTEXT_SWITCH:
			self._event_end(entry.tb, eventtype.CONTEXT_SWITCH,
				warn=(self.firstswitch == False))
			self.firstswitch = False

			pid = entry.data
			key = "PID%s" % pid
			if key not in self.items:
				id = "%s" % pid
				name = entry.comm
				self.items[key] = eventsource(id, name,
						eventtype.CONTEXT_SWITCH)

			# We need to update name at each context switch
			# to catch the process name after we exec
			# (instead of the process name at fork)
			if entry.tb > self.items[key].nametb:
				self.items[key].nametb = entry.tb
				self.items[key].name = entry.comm

			if len(self.eventstack) != 0:
				print "WARNING: eventstack corrupt at %d, " \
					"statistics may be corrupted" % (
						entry.tb)
				self.eventstack = []

			self._event_start(entry.tb, eventtype.CONTEXT_SWITCH,
				key)

		elif entry.event == eventtype.LOST_SAMPLES:
			samples = entry.data
			print "WARNING: %d samples lost on cpu %d" % (samples,
				entry.cpu)

		elif entry.event == eventtype.INTERRUPT_ENTRY:
			key = "external_interrupt"
			if key not in self.items:
				name = "external_interrupt"
				self.items[key] = eventsource("IRQ", name,
					eventtype.INTERRUPT_ENTRY)
			self._event_start(entry.tb, eventtype.INTERRUPT_ENTRY,
				key)

		elif entry.event == eventtype.INTERRUPT_EXIT:
			self._event_end(entry.tb, eventtype.INTERRUPT_ENTRY)

		elif entry.event == eventtype.INTERRUPT_HANDLER_ENTRY:
			irq = entry.data
			key = "IRQ%d" % irq
			if key not in self.items:
				name = self.i.lookup(irq)
				self.items[key] = eventsource("IRQ", name,
					eventtype.INTERRUPT_HANDLER_ENTRY)
			self._event_start(entry.tb,
				eventtype.INTERRUPT_HANDLER_ENTRY, key)

		elif entry.event == eventtype.INTERRUPT_HANDLER_EXIT:
			self._event_end(entry.tb,
				eventtype.INTERRUPT_HANDLER_ENTRY)

		elif entry.event == eventtype.TIMER_INTERRUPT_ENTRY:
			key = "timer_interrupt"
			if key not in self.items:
				name = "timer_interrupt"
				self.items[key] = eventsource("TIMER", name,
						eventtype.TIMER_INTERRUPT_ENTRY)

			self._event_start(entry.tb,
				eventtype.TIMER_INTERRUPT_ENTRY, key)

		elif entry.event == eventtype.TIMER_INTERRUPT_EXIT:
			self._event_end(entry.tb,
				eventtype.TIMER_INTERRUPT_ENTRY)

		elif entry.event == eventtype.WORKQUEUE_ENTRY:
			func = entry.data
			key = "WORKQUEUE%d" % func
			if key not in self.items:
				name = self.ksyms.lookup(func)
				self.items[key] = eventsource("EVENT", name,
						eventtype.WORKQUEUE_ENTRY)

			self._event_start(entry.tb, eventtype.WORKQUEUE_ENTRY,
				key)

		elif entry.event == eventtype.WORKQUEUE_EXIT:
			self._event_end(entry.tb, eventtype.WORKQUEUE_ENTRY)

		elif entry.event == eventtype.TIMER_ENTRY:
			func = entry.data
			key = "TIMER%d" % func
			if key not in self.items:
				name = self.ksyms.lookup(func)
				self.items[key] = eventsource("TIMER", name,
						eventtype.TIMER_ENTRY)

			self._event_start(entry.tb, eventtype.TIMER_ENTRY, key)

		elif entry.event == eventtype.TIMER_EXIT:
			self._event_end(entry.tb, eventtype.TIMER_ENTRY)

		elif entry.event == eventtype.SOFTIRQ_ENTRY:
			irq = entry.data
			key = "SOFTIRQ%d" % irq
			if key not in self.items:
				name = self.softirq.lookup(irq)
				self.items[key] = eventsource("SIRQ", name,
						eventtype.SOFTIRQ_ENTRY)

			self._event_start(entry.tb, eventtype.SOFTIRQ_ENTRY,
				key)

		elif entry.event == eventtype.SOFTIRQ_EXIT:
			self._event_end(entry.tb, eventtype.SOFTIRQ_ENTRY)

		elif entry.event == eventtype.TASKLET_ENTRY:
			func = entry.data
			key = "TASKLET%d" % func
			if key not in self.items:
				name = self.ksyms.lookup(func)
				self.items[key] = eventsource("TLET", name,
						eventtype.TASKLET_ENTRY)

			self._event_start(entry.tb, eventtype.TASKLET_ENTRY,
				key)

		elif entry.event == eventtype.TASKLET_EXIT:
			self._event_end(entry.tb, eventtype.TASKLET_ENTRY)

		elif entry.event == eventtype.HCALL_ENTRY:
			opcode = entry.data
			key = "HCALL%d" % opcode
			if key not in self.items:
				name = self.hcall.lookup(opcode)
				self.items[key] = eventsource("HVC", name,
						eventtype.HCALL_ENTRY)

			self._event_start(entry.tb, eventtype.HCALL_ENTRY,
				key)

		elif entry.event == eventtype.HCALL_EXIT:
			self._event_end(entry.tb, eventtype.HCALL_ENTRY)

		elif entry.event == eventtype.OPAL_ENTRY:
			opcode = entry.data
			key = "OPAL%d" % opcode
			if key not in self.items:
				name = self.opal.lookup(opcode)
				self.items[key] = eventsource("OPAL", name,
						eventtype.OPAL_ENTRY)

			self._event_start(entry.tb, eventtype.OPAL_ENTRY,
				key)

		elif entry.event == eventtype.OPAL_EXIT:
			self._event_end(entry.tb, eventtype.OPAL_ENTRY)


		elif entry.event == eventtype.PHYP_ENTRY:
			reason = entry.data
			key = "phyp%d" % reason
			if key not in self.items:
				name = dtl.entry.preempt_reasons[reason]
				self.items[key] = eventsource("PHYP", name,
						eventtype.PHYP_ENTRY)

			self._event_start(entry.tb, eventtype.PHYP_ENTRY, key)

		elif entry.event == eventtype.PHYP_EXIT:
			self._event_end(entry.tb, eventtype.PHYP_ENTRY)

		else:
			print 'WARNING: unknown event %d' % entry.event

	def print_results(self, sort_by_max = True):
		print 'pid   name                       count    total(ms)' \
			'   min(ms)   max(ms)   avg(ms)   period(ms)'

		format =     '%5s %-24s %7d %12.3f %9.3f %9.3f %9.3f %12.3f'
		res = []

		for k, v in self.items.iteritems():
			if len(v.active) > 0:
				a = v.active
				i = v.inactive

				if len(i):
					p = self.tb.to_ms(float(sum(i))/len(i))
				else:
					p = 0

				str = format % (v.id, v.name, len(a),
					self.tb.to_ms(sum(a)),
					self.tb.to_ms(min(a)),
					self.tb.to_ms(max(a)),
					self.tb.to_ms(float(sum(a)) / len(a)),
					p);

				if sort_by_max == True:
					res.append((max(a), str))
				else:
					res.append((sum(a), str))

		for r in sorted(res, reverse=True):
			(junk, str) = r
			print str


class trace(object):
	prevtb = None
	warned = False
	curspace = 2
	vals = []

	def __init__(self, procdir = '/proc'):
		self.tb = timebase(procdir + '/cpuinfo')
		self.ksyms = kallsyms(procdir + '/kallsyms')
		self.irqs = interrupts(procdir + '/interrupts')
		self.softirq = softirqs()
		self.hcall = hcalls()
		self.opal = opal_calls()

	def _space(self, entry):
		ret = ""

		if entry == 0:
			self.curspace -= 2
			if self.curspace < 2:
				self.curspace = 2

		for i in range(self.curspace):
			ret = ret + " "

		if entry:
			self.curspace += 2

		return ret

	def sample(self, entry):
		# Store as a tuple so we can easily sort by timebase
		self.vals.append((entry.tb, entry))

	def _print_one(self, entry, relative, absolute):

		if self.prevtb == None:
			self.prevtb = entry.tb

		if entry.tb < self.prevtb:
			if self.warned == False:
				self.warned = True
				print 'WARNING: time went backwards at %d' % (
					self.prevtb)
			return

		if relative:
			print '%14.3f\t' % (
				self.tb.to_us(entry.tb -self.prevtb)),

		if absolute:
			print '%d\t' % entry.tb,

		self.prevtb = entry.tb

		print '%d\t' % entry.cpu,

		if entry.event == eventtype.CONTEXT_SWITCH:
			print 'ctx switch %d %s' % (entry.data, entry.comm)
			# Reset our indent, in case we lost samples
			self.curspace = 2

		elif entry.event == eventtype.LOST_SAMPLES:
			print 'lost samples: %d' % entry.data

		elif entry.event == eventtype.INTERRUPT_ENTRY:
			print '%sirq entry' % (self._space(1))

		elif entry.event == eventtype.INTERRUPT_EXIT:
			print '%sirq exit' % (self._space(0))

		elif entry.event == eventtype.INTERRUPT_HANDLER_ENTRY:
			print '%sirq %d (%s) entry' % (self._space(1),
				entry.data, self.irqs.lookup(entry.data))

		elif entry.event == eventtype.INTERRUPT_HANDLER_EXIT:
			print '%sirq %d (%s) exit' % (self._space(0),
				entry.data, self.irqs.lookup(entry.data))

		elif entry.event == eventtype.TIMER_INTERRUPT_ENTRY:
			print '%stimer irq entry' % (self._space(1))

		elif entry.event == eventtype.TIMER_INTERRUPT_EXIT:
			print '%stimer irq exit' % (self._space(0))

		elif entry.event == eventtype.TIMER_ENTRY:
			print '%stimer (%s) entry' % (self._space(1),
				self.ksyms.lookup(entry.data))

		elif entry.event == eventtype.TIMER_EXIT:
			print '%stimer (%s) exit' % (self._space(0),
				self.ksyms.lookup(entry.data))

		elif entry.event == eventtype.SOFTIRQ_ENTRY:
			print '%ssoftirq (%s) entry' % (self._space(1),
				self.softirq.lookup(entry.data))

		elif entry.event == eventtype.SOFTIRQ_EXIT:
			print '%ssoftirq (%s) exit' % (self._space(0),
				self.softirq.lookup(entry.data))

		elif entry.event == eventtype.WORKQUEUE_ENTRY:
			print '%sworkqueue (%s) entry' % (self._space(1),
				self.ksyms.lookup(entry.data))

		elif entry.event == eventtype.WORKQUEUE_EXIT:
			print '%sworkqueue (%s) exit' % (self._space(0),
				self.ksyms.lookup(entry.data))

		elif entry.event == eventtype.TASKLET_ENTRY:
			print '%stasklet (%s) entry' % (self._space(1),
				self.ksyms.lookup(entry.data))

		elif entry.event == eventtype.TASKLET_EXIT:
			print '%stasklet (%s) exit' % (self._space(0),
				self.ksyms.lookup(entry.data))

		elif entry.event == eventtype.HCALL_ENTRY:
			print '%shcall (%s) entry' % (self._space(1),
				self.hcall.lookup(entry.data))

		elif entry.event == eventtype.HCALL_EXIT:
			print '%shcall (%s) exit' % (self._space(0),
				self.hcall.lookup(entry.data))

		elif entry.event == eventtype.OPAL_ENTRY:
			print '%sopal (%s) entry' % (self._space(1),
				self.opal.lookup(entry.data))

		elif entry.event == eventtype.OPAL_EXIT:
			print '%sopal (%s) exit' % (self._space(0),
				self.opal.lookup(entry.data))

		elif entry.event == eventtype.PHYP_ENTRY:
			print 'phyp entry (%s)' % (
				dtl.entry.preempt_reasons[entry.data])

		elif entry.event == eventtype.PHYP_EXIT:
			print 'phyp exit'

		else:
			print 'WARNING: unknown event %d' % entry.event

	def print_results(self, relative=True, absolute=False):
		for (tb, entry) in sorted(self.vals):
			self._print_one(entry, relative, absolute)

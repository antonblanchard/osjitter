import struct
import osjitter

class entry(object):
	format = '>B B H I I I Q Q Q Q'
	size = struct.calcsize(format)

	dispatch_reasons = ['external interrupt',
			    'firmware internal event',
			    'H_PROD',
			    'decrementer interrupt',
			    'system reset',
			    'firmware internal event',
			    'conferred cycles',
			    'time slice',
			    'virtual memory page fault']

	preempt_reasons = ['unused',
			   'firmware internal event',
			   'H_CEDE',
			   'H_CONFER',
			   'time slice',
			   'migration/hibernation page fault',
			   'virtual memory page pault']

	def _parse(self, buf, start):
		end = start + self.size

		(self._dispatch_reason,
		self._preempt_reason,
		self._processor_id,
		self._enqueue_to_dispatch_time,
		self._ready_to_enqueue_time,
		self._waiting_to_ready_time,
		self._timebase,
		self._fault_addr,
		self._srr0,
		self._srr1) = struct.unpack(self.format, buf[start:end])


	def parse_start(self, buf, start, cpu):
		self._parse(buf, start)

		self.tb = self._timebase
		self.data = self._preempt_reason
		self.cpu = cpu
		self.event = osjitter.eventtype.PHYP_ENTRY

		return self.size

	def parse_end(self, buf, start, cpu):
		self._parse(buf, start)

		self.tb = self._timebase + self._enqueue_to_dispatch_time + \
			self._ready_to_enqueue_time + \
			self._waiting_to_ready_time
		self.data = self._preempt_reason
		self.cpu = cpu
		self.event = osjitter.eventtype.PHYP_EXIT

		return self.size

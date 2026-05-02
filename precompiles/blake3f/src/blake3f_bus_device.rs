use std::ops::Add;

use precompiles_common::MemProcessor;
use zisk_common::STEP;
use zisk_common::{
    BusDevice, BusDeviceMode, BusId, Counter, Metrics, B, OPERATION_BUS_ID, OP_TYPE,
};
use zisk_core::ZiskOperationType;

use crate::{generate_blake3f_mem_inputs, skip_blake3f_mem_inputs};

pub struct Blake3fCounterInputGen {
    counter: Counter,
    mode: BusDeviceMode,
}

impl Blake3fCounterInputGen {
    pub fn new(mode: BusDeviceMode) -> Self {
        Self { counter: Counter::default(), mode }
    }

    pub fn inst_count(&self, op_type: ZiskOperationType) -> Option<u64> {
        (op_type == ZiskOperationType::Blake3).then_some(self.counter.inst_count)
    }

    #[inline(always)]
    pub fn process_data<P: MemProcessor>(
        &mut self,
        bus_id: &BusId,
        data: &[u64],
        mem_processors: &mut P,
    ) -> bool {
        debug_assert!(*bus_id == OPERATION_BUS_ID);

        if data[OP_TYPE] as u32 != ZiskOperationType::Blake3 as u32 {
            return true;
        }

        let step_main = data[STEP];
        let addr_main = data[B] as u32;

        match self.mode {
            BusDeviceMode::Counter => {
                self.measure(data);
                generate_blake3f_mem_inputs(addr_main, step_main, data, true, mem_processors);
            }
            BusDeviceMode::CounterAsm => {
                self.measure(data);
            }
            BusDeviceMode::InputGenerator => {
                if skip_blake3f_mem_inputs(addr_main, data, mem_processors) {
                    return true;
                }
                generate_blake3f_mem_inputs(addr_main, step_main, data, false, mem_processors);
            }
        }

        true
    }
}

impl Metrics for Blake3fCounterInputGen {
    #[inline(always)]
    fn measure(&mut self, _data: &[u64]) {
        self.counter.update(1);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl Add for Blake3fCounterInputGen {
    type Output = Blake3fCounterInputGen;

    fn add(self, other: Self) -> Blake3fCounterInputGen {
        Blake3fCounterInputGen { counter: &self.counter + &other.counter, mode: self.mode }
    }
}

impl BusDevice<u64> for Blake3fCounterInputGen {
    fn as_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

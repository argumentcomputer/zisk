use std::sync::Arc;

use fields::PrimeField64;
use pil_std_lib::Std;
use zisk_common::{BusDeviceMode, ComponentBuilder, Instance, InstanceCtx, InstanceInfo, Planner};
use zisk_core::ZiskOperationType;
use zisk_pil::Blake3fTrace;

use crate::{Blake3fCounterInputGen, Blake3fInstance, Blake3fPlanner, Blake3fSM};

/// The `Blake3fManager` struct represents the Blake3f manager,
/// which is responsible for managing the Blake3f state machine and its planner.
#[allow(dead_code)]
pub struct Blake3fManager<F: PrimeField64> {
    blake3f_sm: Arc<Blake3fSM<F>>,
}

impl<F: PrimeField64> Blake3fManager<F> {
    pub fn new(std: Arc<Std<F>>) -> Arc<Self> {
        let blake3f_sm = Blake3fSM::new(std);
        Arc::new(Self { blake3f_sm })
    }

    pub fn build_blake3f_counter(&self, asm_execution: bool) -> Blake3fCounterInputGen {
        match asm_execution {
            true => Blake3fCounterInputGen::new(BusDeviceMode::CounterAsm),
            false => Blake3fCounterInputGen::new(BusDeviceMode::Counter),
        }
    }

    pub fn build_blake3f_input_generator(&self) -> Blake3fCounterInputGen {
        Blake3fCounterInputGen::new(BusDeviceMode::InputGenerator)
    }
}

impl<F: PrimeField64> ComponentBuilder<F> for Blake3fManager<F> {
    fn build_planner(&self) -> Box<dyn Planner> {
        let num_available = self.blake3f_sm.num_available_blake3fs;

        Box::new(Blake3fPlanner::new().add_instance(InstanceInfo::new(
            Blake3fTrace::<()>::AIRGROUP_ID,
            Blake3fTrace::<()>::AIR_ID,
            num_available,
            ZiskOperationType::Blake3,
        )))
    }

    fn build_instance(&self, ictx: InstanceCtx) -> Box<dyn Instance<F>> {
        match ictx.plan.air_id {
            id if id == Blake3fTrace::<()>::AIR_ID => {
                Box::new(Blake3fInstance::new(self.blake3f_sm.clone(), ictx))
            }
            _ => {
                panic!(
                    "Blake3fManager::build_instance() Unsupported air_id: {:?}",
                    ictx.plan.air_id
                )
            }
        }
    }
}

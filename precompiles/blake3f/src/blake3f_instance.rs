//! The `Blake3fInstance` module defines an instance to perform the witness computation
//! for the Blake3 Compression State Machine.

use crate::{Blake3fInput, Blake3fSM, OPERATION_BUS_BLAKE3F_DATA_SIZE};
use fields::PrimeField64;
use proofman_common::{AirInstance, ProofCtx, ProofmanResult, SetupCtx};
use std::{any::Any, collections::HashMap, sync::Arc};
use zisk_common::ChunkId;
use zisk_common::{
    BusDevice, BusId, CheckPoint, CollectSkipper, Instance, InstanceCtx, InstanceType, PayloadType,
    OPERATION_BUS_ID, OP_TYPE,
};
use zisk_core::ZiskOperationType;
use zisk_pil::{Blake3fTraceRow, Blake3fTraceRowPacked, BLAKE_3_F_AIR_IDS};

pub struct Blake3fInstance<F: PrimeField64> {
    blake3f_sm: Arc<Blake3fSM<F>>,
    ictx: InstanceCtx,
}

impl<F: PrimeField64> Blake3fInstance<F> {
    pub fn new(blake3f_sm: Arc<Blake3fSM<F>>, ictx: InstanceCtx) -> Self {
        Self { blake3f_sm, ictx }
    }

    pub fn build_blake3f_collector(&self, chunk_id: ChunkId) -> Blake3fCollector {
        assert_eq!(
            self.ictx.plan.air_id, BLAKE_3_F_AIR_IDS[0],
            "Blake3fInstance: Unsupported air_id: {:?}",
            self.ictx.plan.air_id
        );

        let meta = self.ictx.plan.meta.as_ref().unwrap();
        let collect_info = meta.downcast_ref::<HashMap<ChunkId, (u64, CollectSkipper)>>().unwrap();
        let (num_ops, collect_skipper) = collect_info[&chunk_id];
        Blake3fCollector::new(num_ops, collect_skipper)
    }
}

impl<F: PrimeField64> Instance<F> for Blake3fInstance<F> {
    /// Computes the witness for the blake3 execution plan.
    ///
    /// Dispatches on the runtime `packed` flag — passing the unpacked or packed
    /// trace row type as a generic parameter to `Blake3fSM::compute_witness`.
    fn compute_witness(
        &self,
        _pctx: &ProofCtx<F>,
        _sctx: &SetupCtx<F>,
        collectors: Vec<(usize, Box<dyn BusDevice<PayloadType>>)>,
        trace_buffer: Vec<F>,
        packed: bool,
    ) -> ProofmanResult<Option<AirInstance<F>>> {
        let inputs: Vec<_> = collectors
            .into_iter()
            .map(|(_, collector)| {
                collector.as_any().downcast::<Blake3fCollector>().unwrap().inputs
            })
            .collect();

        if packed {
            Ok(Some(
                self.blake3f_sm
                    .compute_witness::<Blake3fTraceRowPacked<F>>(&inputs, trace_buffer)?,
            ))
        } else {
            Ok(Some(
                self.blake3f_sm.compute_witness::<Blake3fTraceRow<F>>(&inputs, trace_buffer)?,
            ))
        }
    }

    fn check_point(&self) -> &CheckPoint {
        &self.ictx.plan.check_point
    }

    fn instance_type(&self) -> InstanceType {
        InstanceType::Instance
    }

    fn build_inputs_collector(&self, chunk_id: ChunkId) -> Option<Box<dyn BusDevice<PayloadType>>> {
        assert_eq!(
            self.ictx.plan.air_id, BLAKE_3_F_AIR_IDS[0],
            "Blake3fInstance: Unsupported air_id: {:?}",
            self.ictx.plan.air_id
        );

        let meta = self.ictx.plan.meta.as_ref().unwrap();
        let collect_info = meta.downcast_ref::<HashMap<ChunkId, (u64, CollectSkipper)>>().unwrap();
        let (num_ops, collect_skipper) = collect_info[&chunk_id];
        Some(Box::new(Blake3fCollector::new(num_ops, collect_skipper)))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub struct Blake3fCollector {
    inputs: Vec<Blake3fInput>,
    num_operations: u64,
    collect_skipper: CollectSkipper,
}

impl Blake3fCollector {
    pub fn new(num_operations: u64, collect_skipper: CollectSkipper) -> Self {
        Self {
            inputs: Vec::with_capacity(num_operations as usize),
            num_operations,
            collect_skipper,
        }
    }

    #[inline(always)]
    pub fn process_data(&mut self, bus_id: &BusId, data: &[PayloadType]) -> bool {
        debug_assert!(*bus_id == OPERATION_BUS_ID);

        if self.inputs.len() == self.num_operations as usize {
            return false;
        }

        if data[OP_TYPE] as u32 != ZiskOperationType::Blake3 as u32 {
            return true;
        }

        if self.collect_skipper.should_skip() {
            return true;
        }

        let blake3f_data: [u64; OPERATION_BUS_BLAKE3F_DATA_SIZE] = data
            [..OPERATION_BUS_BLAKE3F_DATA_SIZE]
            .try_into()
            .expect("Blake3fCollector: Failed to convert data");
        self.inputs.push(Blake3fInput::from(&blake3f_data));

        self.inputs.len() < self.num_operations as usize
    }
}

impl BusDevice<PayloadType> for Blake3fCollector {
    fn as_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

use std::ptr;

use common::common_error::CommonError;

pub fn slice_to_u16(slice: &[u8]) -> Result<u16, CommonError> {
    if slice.len() < 2 {
        return Err(CommonError::ConvertErr);
    }

    let value = (slice[1] as u16) << 8;
    Ok(value | slice[0] as u16)
}

pub fn slice_to_u32(slice: &[u8]) -> Result<u32, CommonError> {
    if slice.len() < 4 {
        return Err(CommonError::ConvertErr);
    }

    let mut value = (slice[3] as u32) << 24;
    value |= (slice[2] as u32) << 16;
    value |= (slice[1] as u32) << 8;
    Ok(value | slice[0] as u32)
}

pub fn u16_to_vec_u8(value: u16) -> Vec<u8> {
    let mut ret: Vec<u8> = vec![0,0];
    ret[0] |= (value & 0xFF) as u8;
    ret[1] |= ((value & (0xFF << 8)) >> 8) as u8;
    ret
}

pub fn u32_to_vec_u8(value: u32) -> Vec<u8> {
    let mut ret: Vec<u8> = vec![0,0,0,0];
    ret[0] |= (value & 0xFF) as u8;
    ret[1] |= ((value & (0xFF << 8)) >> 8) as u8;
    ret[2] |= ((value & (0xFF << 16)) >> 16) as u8;
    ret[3] |= ((value & (0xFF << 24)) >> 24) as u8;
    ret
}

pub unsafe fn write_array_volatile(dst: *mut u8, val: u8, count: usize) {
    for i in 0..count {
        ptr::write_volatile(dst.offset(i as isize), val);
    }
}


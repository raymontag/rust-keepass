pub mod v1kpdb;
pub mod v1error;
pub mod v1group;
pub mod v1entry;
pub mod v1header;

mod common;
mod crypter;
mod parser;

#[cfg(test)]
mod tests_v1kpdb;
mod tests_parser;
mod tests_crypter;

use std::rc::Weak;

use self::v1error::V1KpdbError;

trait GetIndex<T> {
    fn get_index(&self, item: &T) -> Result<usize, V1KpdbError>;
}

impl<T: Eq> GetIndex<T> for Vec<T> {
    fn get_index(&self, item: &T) -> Result<usize, V1KpdbError> {
        for index in 0..self.len() {
            if self[index] == *item {
                return Ok(index);
            }
        }

        Err(V1KpdbError::IndexErr)
    }
}

impl<T: Eq> GetIndex<T> for Vec<Weak<T>> {
    fn get_index(&self, item: &T) -> Result<usize, V1KpdbError> {
        for index in 0..self.len() {
            if let Some(cmp_item) = self[index].upgrade() {
                if *cmp_item == *item {
                    return Ok(index);
                }
            } else {
                return Err(V1KpdbError::WeakErr);
            }
        }

        Err(V1KpdbError::IndexErr)
    }
}

use std::cell::RefCell;
use std::rc::Rc;

use super::tm::Tm;

pub struct V1Group {
    pub id:          u32, 
    pub title:       String,
    pub image:       u32,
    pub level:       u16,
    pub creation:    Tm,
    pub last_mod:    Tm,
    pub last_access: Tm,
    pub expire:      Tm,
    pub flags:       u32,
    pub parent:      Option<Rc<RefCell<V1Group>>>,
    //pub children:    Vec<Box<V1Group>>,
    //entries: Vec<Box<V1Entry>>,
    //db: Box<Option<V1Kpdb>>,
}

impl V1Group {
    pub fn new() -> V1Group {
        V1Group { id:          0, 
                  title:       "".to_string(),
                  image:       0,
                  level:       0,
                  creation:    Tm::new(),
                  last_mod:    Tm::new(),
                  last_access: Tm::new(),
                  expire:      Tm::new(),
                  flags:       0,
                  parent:      None,
                  //children:    vec![],
                  //entries: Vec<V1Entry>,
                  //db: box None,
        }
    }
}

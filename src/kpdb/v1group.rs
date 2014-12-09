use super::tm::Tm;

pub struct V1Group<'a> {
    pub id:          u32, 
    pub title:       String,
    pub image:       u32,
    pub level:       u16,
    pub creation:    Tm,
    pub last_mod:    Tm,
    pub last_access: Tm,
    pub expire:      Tm,
    pub flags:       u32,
    pub children:    Vec<&'a Box<V1Group<'a>>>,
    //entries: Vec<Box<V1Entry>>,
    //db: Box<Option<V1Kpdb>>,
}

impl<'a> V1Group<'a> {
    pub fn new() -> V1Group<'a> {
        V1Group { id:          0, 
                  title:       "".to_string(),
                  image:       0,
                  level:       0,
                  creation:    Tm::new(),
                  last_mod:    Tm::new(),
                  last_access: Tm::new(),
                  expire:      Tm::new(),
                  flags:       0,
                  //parent:      None,
                  children:    vec![],
                  //entries: Vec<V1Entry>,
                  //db: box None,
        }
    }
}

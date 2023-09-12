pub trait BuildVec<T> {
    fn build_with(self, elements: &Self) -> Self;
    fn build_with_slice(self, elements: &[T]) -> Self;
}


impl<T> BuildVec<T> for Vec<T> where T: Clone {
    fn build_with(self, elements: &Self) -> Self {
        let mut result = self.clone();
        result.append(&mut elements.clone());
        return result;
    }

    fn build_with_slice(self, elements: &[T]) -> Self {
        let mut result = self.clone();
        result.append(&mut elements.to_vec());
        return result;
    }
}

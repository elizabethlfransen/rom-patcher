/// Builder pattern utility for vectors
pub trait BuildVec<T> {

    fn build_with(self, elements: &Self) -> Self;

    fn build_with_slice(self, elements: &[T]) -> Self;
}


impl<T> BuildVec<T> for Vec<T> where T: Clone {
    /// Returns a new vector with all the existing elements and `elements` appended to it
    ///
    /// # Examples
    ///
    /// ```
    /// let my_vec = Vec::new()
    ///     .build_with_slice(&[0,1,2]);
    /// ```
    fn build_with(self, elements: &Self) -> Self {
        let mut result = self.clone();
        result.append(&mut elements.clone());
        return result;
    }
    /// Returns a new vector with all the existing elements and `elements` appended to it
    ///
    /// # Examples
    ///
    /// ```
    /// let my_vec = Vec::new()
    ///     .build_with(&vec![0,1,2]);
    /// ```
    fn build_with_slice(self, elements: &[T]) -> Self {
        let mut result = self.clone();
        result.append(&mut elements.to_vec());
        return result;
    }
}

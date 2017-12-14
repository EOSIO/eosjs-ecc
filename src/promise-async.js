
/**
  Convert a synchronous function into a asynchronous one (via setTimeout)
  wrapping it in a promise.  This does not expect the function to have a
  callback paramter.

  @arg {function} func - non-callback function

  @example promiseAsync(myfunction)
*/
module.exports = func => (
  (...args) => (
    new Promise((resolve, reject) => {
      setTimeout(() => {
        try {
          resolve(func(...args))
        } catch(err) {
          reject(err)
        }
      })
    })
  )
)

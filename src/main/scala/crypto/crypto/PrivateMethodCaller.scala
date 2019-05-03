package crypto.privateMethodCaller


// Usage:
////   p(instance)('privateMethod)(arg1, arg2, arg3)
//
//class PrivateMethodCaller(x: AnyRef, methodName: String) {
//  def apply(_args: Any*): Any = {
//    val args = _args.map(_.asInstanceOf[AnyRef])
//    def _parents: Stream[Class[_]] = Stream(x.getClass) #::: _parents.map(_.getSuperclass)
//    val parents = _parents.takeWhile(_ != null).toList
//    val methods = parents.flatMap(_.getDeclaredMethods)
//    val method = methods.find(_.getName == methodName).getOrElse(throw new IllegalArgumentException("Method " + methodName + " not found"))
//    method.setAccessible(true)
//    method.invoke(x, args : _*)
//  }
//}
//
//class PrivateMethodExposer(x: AnyRef) {
//  def apply(method: scala.Symbol): PrivateMethodCaller = new PrivateMethodCaller(x, method.name)
//}

//
// def p(x: AnyRef): PrivateMethodExposer = new PrivateMethodExposer(x)

class PrivateMethodCaller {
  def callPrivateTyped(obj: AnyRef, methodName: String, parameters:(AnyRef,Class[_])*) = {
    val parameterValues = parameters.map(_._1)
    val parameterTypes = parameters.map(_._2)
    val method = obj.getClass.getDeclaredMethod(methodName, parameterTypes:_*)
    method.setAccessible(true)
    println("Call .asInstanceOf[%s] to cast" format method.getReturnType.getName)
    method.invoke(obj, parameterValues:_*)
  }

  // for convenience
  def callPrivate(obj: AnyRef, methodName: String, parameters:AnyRef*) = {
    callPrivateTyped(obj, methodName, parameters.map(c => (c, c.getClass)):_*)
  }
}
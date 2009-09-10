package = newpackage()
package.name = "cardlib"
package.language = "c++"
package.kind = "lib"

package.files = {
  matchfiles("*.h","*.cpp"),
}

package.buildflags = {"extra-warnings","fatal-warnings"}

if (linux) then
	package.includepaths = { "/usr/include/PCSC" }
end
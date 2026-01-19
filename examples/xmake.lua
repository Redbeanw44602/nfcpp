target('example')
    set_kind('phony')
    set_warnings('all', 'extra', {public = true})
    set_languages('c++23', {public = true})
    add_includedirs('$(projectdir)/src', {public = true})
    add_deps('nfcpp', {public = true})

includes('mifare_auth')

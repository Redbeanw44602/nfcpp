add_rules('mode.debug', 'mode.release')

add_requires('libnfc')
    
set_version('0.1.0')

target('nfc-extra')
    set_kind('headeronly')
    add_headerfiles('src/nfc-extra/*.h')

target('crapto1')
    set_kind('static')
    set_languages('c99')
    add_files('src/crapto1/*.c')
    add_headerfiles('src/crapto1/*.h')

target('nfcpp')
    set_kind('headeronly')
    add_headerfiles('src/*.hpp')
    add_packages('libnfc', {public = true})
    add_deps('nfc-extra')
    add_deps('crapto1')

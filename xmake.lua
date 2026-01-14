add_rules('mode.debug', 'mode.release')

add_requires('libnfc')
    
set_version('0.1.0')

option('crapto1')
    set_default(false)
    set_showmenu(true)
    set_description('Enable crapto1 support, you must comply with the GPLv3 license.')

target('nfc-extra')
    set_kind('headeronly')
    add_headerfiles('src/nfc-extra/*.h')

if has_config('crapto1') then
target('crapto1')
    set_kind('static')
    set_languages('c99')
    add_files('src/crapto1/*.c')
    add_headerfiles('src/crapto1/*.h')
end

target('nfcpp')
    set_kind('headeronly')
    add_headerfiles('src/*.hpp')
    add_packages('libnfc', {public = true})
    add_deps('nfc-extra')
    add_options('crapto1')
    on_load(function (target) 
        if has_config('crapto1') then
            target:add('deps', 'crapto1')
            target:add('defines', 'NFCPP_ENABLE_CRAPTO1=1', {public = true})
        end
    end)

includes('examples/xmake.lua')

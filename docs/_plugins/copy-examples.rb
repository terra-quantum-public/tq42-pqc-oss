require 'fileutils'

Jekyll::Hooks.register :site, :after_init do |jekyll|
    FileUtils.mkdir_p '_includes'
    FileUtils.cp_r '../examples', '_includes'
end

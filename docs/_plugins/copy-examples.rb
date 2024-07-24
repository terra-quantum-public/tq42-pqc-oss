require 'fileutils'

Jekyll::Hooks.register :site, :after_init do |jekyll|
    FileUtils.cp_r '../examples', '_includes'
end

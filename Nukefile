;; source files
(set @m_files     (filelist "^objc/.*.m$"))
(set @nu_files 	  (filelist "^nu/.*nu$"))

(set SYSTEM ((NSString stringWithShellCommand:"uname") chomp))

(case SYSTEM
      ("Darwin"
               (set @arch (list "x86_64"))
               (set @cflags "-g -Wno-deprecated-declarations -std=gnu99 -DDARWIN -DRadCrypto_OpenSSL")
               (set @ldflags "-framework Foundation -framework Nu -lcrypto -lssl"))
      ("Linux"
              (set @arch (list "x86_64"))
              (set gnustep_flags ((NSString stringWithShellCommand:"gnustep-config --objc-flags") chomp))
              (set gnustep_libs ((NSString stringWithShellCommand:"gnustep-config --base-libs") chomp))
              (set @cflags "-g -fobjc-nonfragile-abi -fobjc-arc -DLINUX -I/usr/local/include #{gnustep_flags} -DRadCrypto_OpenSSL")
              (set @ldflags "#{gnustep_libs} -lNu -lcrypto -lssl -luuid"))
      (else nil))


;; framework description
(set @framework "RadCrypto")
(set @framework_identifier "com.radtastical.radcrypto")
(set @framework_creator_code "????")

(compilation-tasks)
(framework-tasks)

(task "clobber" => "clean" is
      (SH "rm -rf #{@framework_dir}"))

(task "default" => "framework")

(task "doc" is (SH "nudoc"))


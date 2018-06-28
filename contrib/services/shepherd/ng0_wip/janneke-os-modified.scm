(use-modules (gnu))
(use-service-modules
;; admin
 base
 mcron
 networking
 ssh)

(use-package-modules
 admin
 ssh
 version-control
 gnunet)

(define %user (getenv "USER"))

(define os
  (operating-system
    (host-name "os")
    (timezone "Europe/Amsterdam")
    (locale "en_US.UTF-8")

    (bootloader
     (grub-configuration
      (device "/dev/sda")))
    
    (file-systems
     (cons* (file-system (mount-point "/")
                         (device "/dev/sda1")
                         (type "ext4"))
            %base-file-systems))
    
    (groups
     (cons* (user-group (name %user))
          %base-groups))
    
    (users
     (cons* (user-account (name %user)
                          (group %user)
                          (password (crypt "" "xx"))
                          (uid 1000)
                          (supplementary-groups '("wheel" "gnunet"))
                          (home-directory (string-append "/home/" %user)))
            %base-user-accounts))

    (packages
     (cons*
      git
      openssh
      gnunet
      %base-packages))

    (services
     (cons*
      (dhcp-client-service)
      (lsh-service #:port-number 2222
                   #:allow-empty-passwords? #t
                   #:root-login? #t)
      (gnunet-service)
      %base-services
      ))))
os

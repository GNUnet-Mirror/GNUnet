;;; plant ---
;;; Copyright (C) 2016, 2017, 2018 Nils Gillmann <gillmann@infotropique.org>
;;;
;;; This file is part of plant.
;;;
;;; plant is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 3 of the License, or (at
;;; your option) any later version.
;;;
;;; plant is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of thye GNU General Public License
;;; along with plant.  If not, see <http://www.gnu.org/licenses/>.

(define-module (infotropique services networking)
  #:use-module (infotropique services)
  #:use-module (infotropique services shepherd)
  #:use-module (infotropique services dbus)
  #:use-module (infotropique system shadow)
  #:use-module (infotropique system pam)
  #:use-module (infotropique packages admin)
  #:use-module (infotropique packages connman)
  #:use-module (infotropique packages linux)
  #:use-module (infotropique packages tor)
  #:use-module (infotropique packages messaging)
  #:use-module (infotropique packages networking)
  #:use-module (infotropique packages ntp)
  #:use-module (infotropique packages wicd)
  #:use-module (infotropique packages gnome)
  #:use-module (infotropique packages gnunet)
  #:use-module (plant gexp)
  #:use-module (plant records)
  #:use-module (plant modules)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-26)
  #:use-module (ice-9 match)
  #:export (gnunet-configuration
            gnunet-configuration?
            gnunet-service
            gnunet-service-type))

;;;
;;; Commentary:
;;; gnunet (GNUnet) related services, mainly gnunet itself.
;;;

;; GENTOO OpenRC:
DONE: depends on "net".
DONE: PIDFILE=/run/gnunet/arm-service.pid
SUID_ROOT_HELPERS=exit, nat-server, nat-client, transport-bluetooth, transport-wlan, vpn

/var/lib/gnunet/.local/share/gnunet/gnunet.conf must be chmod 600 and chown gnunet:gnunet
/var/lib/gnunet/.cache/gnunet must exist.
/usr/lib/gnunet/libexec/gnunet-helper-SUID_ROOT_HELPERS must be s+u (--> suid)

/usr/lib/gnunet/libexec/gnunet-helper-dns must be: chown root:gnunetdns and chmod 4750
/usr/lib/gnunet/libexec/gnunet-service-dns must be: chown gnunet:gnunetdns and chmod 2750

directory with PID file must then be chowned by gnunet:gnunet

user gnunet startet dann /usr/lib/gnunet/libexec/gnunet-service-arm -d

stop process hat:
start-stop-daemon --stop --signal QUIT --pidfile ${PIDFILE}
sleep 1
killall -u gnunet
sleep 1
rm -rf /tmp/gnunet-gnunet-runtime >/dev/null 2>&1
rm -rf /tmp/gnunet-system-runtime >/dev/null 2>&1

/etc/nsswitch.conf kriegt den eintrag:
hosts:       files gns [NOTFOUND=return] dns

und die dateien die in der source rumliegen bzgl nss müssen noch kopiert werden
UND nss muss sie finden.



(define-record-type* <gnunet-configuration>
  gnunet-configuration make-gnunet-configuration
  gnunet-configuration?
  (package           gnunet-configuration-package
                     (default gnunet))
  (config-file       gnunet-configuration-config-file
                     (default %default-gnunet-config-file)))

;; TODO: [PATHS] DEFAULTCONFIG = ?
(define %default-gnunet-config-file
  (plain-file "gnunet.conf" "
[PATHS]
SERVICEHOME = /var/lib/gnunet
GNUNET_CONFIG_HOME = /var/lib/gnunet

[arm]
SYSTEM_ONLY = YES
USER_ONLY = NO

[nat]
BEHIND_NAT = YES
ENABLE_UPNP = NO
USE_LOCALADDR = NO
DISABLEV6 = YES

[hostlist]
OPTIONS = -b -e
"))

(define gnunet-shepherd-service
  (match-lambda
    (($ <gnunet-configuration> package config-file)
     (list (shepherd-service
            (provision '(gnunet))
            ;; do we require networking? arm will try to reconnect until a connection
            ;; exists (again), but we might also set up vpn and not succeed at service
            ;; boot time as well as the general certificate issue we have especially on
            ;; Guix-on-GuixSD systems.
            (requirement '(loopback))
            (documentation "Run the GNUnet service.")
            (start
             (let ((gnunet
                    (file-append package "/lib/gnunet/libexec/gnunet-service-arm")))
               #~(make-forkexec-constructor
                  (list #$gnunet "-c" #$config-file)
                  #:log-file "/var/log/gnunet.log"
                  #:pid-file "/var/run/gnunet/arm-service.pid")))
            (stop
             #~(make-kill-destructor)))))))

(define %gnunet-accounts
  (list (user-group
         (name "gnunetdns")
         (system? #t))
        (user-group
         (name "gnunet")
         (system? #t))
        (user-account
         (name "gnunet")
         (group "gnunet")
         (system? #t)
         (comment "GNUnet system user")
         (home-directory "/var/lib/gnunet")
         (shell #~(string-append #$shadow "/sbin/nologin")))))

;; TODO: setuids.
;; TODO: certificate issues -- gnunet should honor CURL_CA_BUNDLE!
(define gnunet-activation
  (match-lambda
    (($ <gnunet-configuration> package config-file)
     (let ((gnunet
            (file-append package "/lib/gnunet/libexec/gnunet-service-arm")))
       #~(begin
           ;; Create the .config + .cache for gnunet user
           (mkdir-p "/var/lib/gnunet/.config/gnunet")
           (mkdir-p "/var/lib/gnunet/.cache/gnunet"))))))

(define gnunet-service-type
  (service-type
   (name 'gnunet)
   (extensions (list (service-extension account-service-type
                                        (const %gnunet-accounts))
                     (service-extension activation-service-type
                                        gnunet-activation)
                     (service-extension profile-service-type
                                        (compose list gnunet-configuration-package))
                     (service-extension shepherd-root-service-type
                                        gnunet-shepherd-service)))))

;;; gnunet.scm ends here

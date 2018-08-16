;;; This file is part of GNUnet.
;;; Copyright (C) 2016, 2017, 2018 GNUnet e.V.
;;;
;;; GNUnet is free software: you can redistribute it and/or modify it
;;; under the terms of the GNU Affero General Public License as published
;;; by the Free Software Foundation, either version 3 of the License,
;;; or (at your option) any later version.
;;;
;;; GNUnet is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; Affero General Public License for more details.
;;;
;;; You should have received a copy of the GNU Affero General Public License
;;; along with this program.  If not, see <http://www.gnu.org/licenses/>.


;;; GNUnet development environment for Guix
;;
;; Depending on whether the search path <gnunet.git>/guix is included or not,
;; the environment has GNUnet from git or uses the GNU distribution's
;; (most likely older) GNUnet package.
;;
;; You can use the development version of GNUnet by passing an extra parameter
;; or setting an environment variable:
;;
;;   --load-path=<gnunet.git>/guix
;;   export GUIX_PACKAGE_PATH=<gnunet.git>/guix
;;
;; To spawn an environment with GNUnet's dependencies installed, run:
;;
;;   guix environment -l guix-env.scm
;;
;; To also make GNUnet available in this environment, run:
;;
;;   guix environment -l guix-env.scm --ad-hoc -l guix-env.scm
;;
;; It is recommented to also pass the '--pure' option to guix, to make sure the
;; environment is not polluted with existing packages.
;;
;; The version of the resulting package is the output of 'git describe --tags'.

(use-modules
 (gnu packages gnunet))

gnunet

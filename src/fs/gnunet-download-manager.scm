#!/bin/sh
exec guile -e main -s "$0" "$@"
!#

;;;    gnunet-download-manager -- Manage GNUnet downloads.
;;;    Copyright (C) 2004  Ludovic Courtès
;;;
;;;    This program is free software; you can redistribute it and/or
;;;    modify it under the terms of the GNU General Public License
;;;    as published by the Free Software Foundation; either version 2
;;;    of the License, or (at your option) any later version.
;;;   
;;;    This program is distributed in the hope that it will be useful,
;;;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;    GNU General Public License for more details.
;;;   
;;;    You should have received a copy of the GNU General Public License
;;;    along with this program; if not, write to the Free Software
;;;    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

;;; Remember ongoing GNUnet downloads so as to be able to resume them
;;; later.  Typical usage is to define the following alias in your
;;; favorite shell:
;;;
;;;    alias gnunet-download='gnunet-download-manager.scm download'
;;;
;;; You may have a ~/.gnunet-download-manager.scm Scheme configuration
;;; file.  In particular, if you would like to be notified of
;;; completed downloads, you may want to add the following line to
;;; your configuration file:
;;;
;;;   (add-hook! *completed-download-hook*
;;;               completed-download-notification-hook)
;;;
;;; This script works fine with GNU Guile 1.6.4, and doesn't run with
;;; Guile 1.4.x.
;;;
;;; Enjoy!
;;; Ludovic Courtès <ludo@chbouib.org>

(use-modules (ice-9 format)
	     (ice-9 optargs)
	     (ice-9 regex)
	     (ice-9 and-let-star)
	     (ice-9 pretty-print)
	     (ice-9 documentation))

;; Overall user settings
(define *debug?* #f)
(define *rc-file* (string-append (getenv "HOME")
				 "/.gnunet-download-manager.scm"))
(define *status-directory* (string-append (getenv "HOME") "/"
					  ".gnunet-download-manager"))
(define *gnunet-download* "gnunet-download")

;; Helper macros
(define-macro (gnunet-info fmt . args)
  `(format #t (string-append *program-name* ": " ,fmt "~%")
	   ,@args))

(define-macro (gnunet-debug fmt . args)
  (if *debug?*
      (cons 'gnunet-info (cons fmt args))
      #t))

(define-macro (gnunet-error fmt . args)
  `(and ,(cons 'gnunet-info (cons fmt args))
	(exit 1)))

(define (exception-string key args)
  "Describe an error, using the format from @var{args}, if available."
  (if (< (length args) 4)
      (format #f "Scheme exception: ~S" key)
      (string-append
       (if (string? (car args))
	   (string-append "In " (car args))
	   "Scheme exception")
       ": "
       (apply format `(#f ,(cadr args) ,@(caddr args))))))


;; Regexps matching GNUnet URIs
(define *uri-base*
  "([[:alnum:]]+)\.([[:alnum:]]+)\.([[:alnum:]]+)\.([0-9]+)")
(define *uri-re*
  (make-regexp (string-append "^gnunet://afs/" *uri-base* "$")
	       regexp/extended))
(define *uri-status-file-re*
  (make-regexp (string-append "^" *uri-base* "$")
	       regexp/extended))


(define (uri-status-file-name directory uri)
  "Return the name of the status file for URI @var{uri}."
  (let ((match (regexp-exec *uri-re* uri)))
    (if (not match)
	(and (gnunet-info "~a: Invalid URI" uri) #f)
	(let ((start (match:start match 1))
	      (end   (match:end   match 4)))
	  (string-append directory "/"
			 (substring uri start end))))))
  
(define (uri-status directory uri)
  "Load the current status alist for URI @var{uri} from @var{directory}."
  (gnunet-debug "uri-status")
  (let ((filename (uri-status-file-name directory uri)))
    (catch 'system-error
	   (lambda ()
	     (let* ((file (open-input-file filename))
		    (status (read file)))
	       (begin
		 (close-port file)
		 status)))
	   (lambda (key . args)
	     (and (gnunet-debug (exception-string key args))
		  '())))))

(define (process-exists? pid)
  (false-if-exception (begin (kill pid 0) #t)))

(define (fork-and-exec directory program . args)
  "Launch @var{program} and return its PID."
  (gnunet-debug "fork-and-exec: ~a ~a" program args)
  (let ((pid (primitive-fork)))
    (if (= 0 pid)
	(begin
	  (if directory (chdir directory))
	  (apply execlp (cons program (cons program args))))
	pid)))

(define* (start-downloader downloader uri options
			   #:key (directory #f))
  "Start the GNUnet downloader for URI @var{uri} with options
@var{options}.  Return an alist describing the download status."
  (catch 'system-error
	 (lambda ()
	   (let* ((pid (apply fork-and-exec
			      `(,(if directory directory (getcwd))
				,downloader
				,@options))))
	     (gnunet-info "Launched process ~a" pid)
	     `((uri . ,uri)
	       (working-directory . ,(if directory directory (getcwd)))
	       (options . ,options)
	       (pid . ,(getpid))
	       (downloader-pid . ,pid))))
	 (lambda (key . args)
	   (gnunet-error (exception-string key args)))))

(define (download-process-alive? uri-status)
  "Return true if the download whose status is that described by
@var{uri-status} is still alive."
  (let ((pid (assoc-ref uri-status 'pid))
	(downloader-pid (assoc-ref uri-status 'downloader-pid)))
    (and (process-exists? pid)
	 (process-exists? downloader-pid))))

(define (start-file-download downloader status-dir uri options)
  "Dowload the file located at @var{uri}, with options @var{options}
and return an updated status alist."
  (gnunet-debug "start-file-download")
  (let ((uri-status (uri-status status-dir uri)))
    (if (null? uri-status)
	(acons 'start-date (current-time)
	       (start-downloader downloader uri options))
	(if (download-process-alive? uri-status)
	    (and (gnunet-info "~a already being downloaded by process ~a"
			      uri (assoc-ref uri-status 'pid))
		 #f)
	    (and (gnunet-info "Resuming download")
		 (let ((start-date (assoc-ref uri-status 'start-date))
		       (dir (assoc-ref uri-status 'working-directory))
		       (options (assoc-ref uri-status 'options)))
		   (acons 'start-date start-date
			  (start-downloader downloader uri options
					    #:directory dir))))))))

(define *completed-download-hook* (make-hook 1))

(define (download-file downloader status-dir uri options)
  "Start downloading file located at URI @var{uri}, with options
@var{options}, resuming it if it's already started."
  (catch 'system-error
	 (lambda ()
	   (and-let* ((status (start-file-download downloader
						   status-dir
						   uri options))
		      (pid (assoc-ref status 'downloader-pid))
		      (filename (uri-status-file-name status-dir
						      uri))
		      (file (open-file filename "w")))

		     ;; Write down the status
		     (pretty-print status file)
		     (close-port file)

		     ;; Wait for `gnunet-download'
		     (gnunet-info "Waiting for process ~a" pid)
		     (let* ((process-status (waitpid pid))
			    (exit-val (status:exit-val (cdr process-status)))
			    (term-sig (status:term-sig (cdr process-status))))

		       ;; Terminate
		       (delete-file filename)
		       (gnunet-info
			"Download completed (PID ~a, exit code ~a)"
			pid exit-val)
		       (let ((ret `((end-date . ,(current-time))
				    (exit-code . ,exit-val)
				    (terminating-signal . ,term-sig)
				    ,@status)))
			 (run-hook *completed-download-hook* ret)
			 ret))))
	   (lambda (key . args)
	     (gnunet-error (exception-string key args)))))

(define (uri-status-files directory)
  "Return the list of URI status files in @var{directory}."
  (catch 'system-error
	 (lambda ()
	   (let ((dir (opendir directory)))
	     (let loop ((filename (readdir dir))
			(file-list '()))
	       (if (eof-object? filename)
		   file-list
		   (if (regexp-exec *uri-status-file-re* filename)
		       (loop (readdir dir)
			     (cons filename file-list))
		       (loop (readdir dir) file-list))))))
	 (lambda (key . args)
	   (gnunet-error (exception-string key args)))))

(define (output-file-option option-list)
  "Return the output file specified in @var{option-list}, false if
anavailable."
  (if (null? option-list)
      #f
      (let ((rest (cdr option-list))
	    (opt (car option-list)))
	(if (null? rest)
	    #f
	    (if (or (string=? opt "-o")
		    (string=? opt "--output"))
		(car rest)
		(output-file-option rest))))))

(define (download-command . args)
  "Start downloading a file using the given `gnunet-download'
arguments."
  (gnunet-debug "download-command")
  (let* ((argc (length args))
	 ;; FIXME: We're assuming the URI is the last argument
	 (uri (car (list-tail args (- argc 1))))
	 (options args))
    (download-file *gnunet-download* *status-directory* uri options)))

(define (status-command . args)
  "Print status info about files being downloaded."
  (for-each (lambda (status)
	      (format #t "~a: ~a~%  ~a~%  ~a~%  ~a~%"
		      (assoc-ref status 'uri)
		      (if (download-process-alive? status)
			  (string-append "running (PID "
					 (number->string (assoc-ref status
								    'pid))
					 ")")
			  "not running")
		      (string-append "Started on "
				     (strftime "%c"
					       (localtime (assoc-ref
							   status
							   'start-date))))
		      (string-append "Directory:   "
				     (assoc-ref status
						'working-directory))
		      (string-append "Output file: "
				     (or (output-file-option (assoc-ref
							      status
							      'options))
					 "<unknown>"))))
	    (map (lambda (file)
		   (uri-status *status-directory*
			       (string-append "gnunet://afs/" file)))
		 (uri-status-files *status-directory*))))

(define (resume-command . args)
  "Resume stopped downloads."
  (for-each (lambda (status)
	      (if (not (download-process-alive? status))
		  (if (= 0 (primitive-fork))
		      (let* ((ret (download-file *gnunet-download*
						 *status-directory*
						 (assoc-ref status 'uri)
						 (assoc-ref status 'options)))
			     (code (assoc-ref ret 'exit-code)))
			(exit code)))))
	    (map (lambda (file)
		   (uri-status *status-directory*
			       (string-append "gnunet://afs/" file)))
		 (uri-status-files *status-directory*))))

(define (killall-command . args)
  "Stop all running downloads."
  (for-each (lambda (status)
	      (if (download-process-alive? status)
		  (let ((pid (assoc-ref status 'pid))
			(dl-pid (assoc-ref status 'downloader-pid)))
		    (and (gnunet-info "Stopping processes ~a and ~a"
				      pid dl-pid)
			 (kill pid 15)
			 (kill dl-pid 15)))))
	    (map (lambda (file)
		   (uri-status *status-directory*
			       (string-append "gnunet://afs/" file)))
		 (uri-status-files *status-directory*))))


(define (help-command . args)
  "Show this help message."
  (format #t "Usage: ~a <command> [options]~%" *program-name*)
  (format #t "Where <command> may be one of the following:~%~%")
  (for-each (lambda (command)
	      (if (not (eq? (cdr command) help-command))
		  (format #t (string-append "   " (car command) ": "
					    (object-documentation
					     (cdr command))
					    "~%"))))
	    *commands*)
  (format #t "~%"))

(define (settings-command . args)
  "Dump the current settings."
  (format #t "Current settings:~%~%")
  (module-for-each (lambda (symbol variable)
		     (if (string-match "^\\*.*\\*$" (symbol->string symbol))
			 (format #t "   ~a: ~a~%"
				 symbol (variable-ref variable))))
		   (current-module))
  (format #t "~%"))

(define (version-command . args)
  "Show version information."
  (format #t "~a ~a.~a (~a)~%"
	  *program-name* *version-major* *version-minor* *version-date*))

;; This hook may be added to *completed-download-hook*.
(define (completed-download-notification-hook status)
  "Notifies of the completion of a file download."
  (let ((msg (string-append "GNUnet download of "
			    (output-file-option
			     (assoc-ref status 'options))
			    " in "
			    (assoc-ref status
				       'working-directory)
			    " complete!")))
    (if (getenv "DISPLAY")
	(waitpid (fork-and-exec #f "xmessage" msg))
	(waitpid (fork-and-exec #f "write"
				(cuserid) msg)))))

;; Available user commands
(define *commands*
  `(("download" . ,download-command)
    ("status"   . ,status-command)
    ("resume"   . ,resume-command)
    ("killall"  . ,killall-command)
    ("settings" . ,settings-command)
    ("version"  . ,version-command)
    ("help"     . ,help-command)
    ("--help"   . ,help-command)
    ("-h"       . ,help-command)))

(define *program-name* "gnunet-download-manager")
(define *version-major* 0)
(define *version-minor* 1)
(define *version-date* "april 2004")

(define (main args)
  (set! *program-name* (basename (car args)))

  ;; Load the user's configuration file
  (if (file-exists? *rc-file*)
      (load *rc-file*))

  ;; Check whether the status directory already exists
  (if (not (file-exists? *status-directory*))
      (begin
	(gnunet-info "Creating status directory ~a..." *status-directory*)
	(catch 'system-error
	       (lambda ()
		 (mkdir *status-directory*))
	       (lambda (key . args)
		 (and (gnunet-error (exception-string key args))
		      (exit 1))))))

  ;; Go ahead
  (if (< (length args) 2)
      (and (format #t "Usage: ~a <command> [options]~%"
		   *program-name*)
	   (exit 1))
      (let* ((command-name (cadr args))
	     (command (assoc-ref *commands* command-name)))
	(if command
	    (apply command (cddr args))
	    (and (gnunet-info "~a command not found" command-name)
		 (exit 1))))))
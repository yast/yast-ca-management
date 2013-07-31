# encoding: utf-8

# ***************************************************************************
#
# Copyright (c) 2004 - 2012 Novell, Inc.
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail,
# you may find current contact information at www.novell.com
#
# ***************************************************************************
# File:        clients/ca_mgm.ycp
# Package:     CA Management
# Summary:     Main file
# Authors:     Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Main file for CA Management. Uses all other files.
module Yast
  class CaMgmClient < Client
    def main
      Yast.import "UI"

      Yast.import "CommandLine"

      #**
      # <h3>CA Management</h3>

      textdomain "ca-management"

      Yast.include self, "ca-management/commandline.rb"

      # Command line definition
      @cmdline = {
        "help"     => _("Managing CA and certificates"),
        "id"       => "ca-mgm",
        "actions"  => {
          "createCA"          => { "help" => _("Create a root CA") },
          "createCertificate" => { "help" => _("Create a certificate of a CA") },
          "createCRL"         => { "help" => _("Create a CRL of a CA") },
          "exportCA"          => { "help" => _("Export a CA to a file") },
          "exportCertificate" => {
            "help" => _("Export a certificate to a file")
          },
          "exportCRL"         => { "help" => _("Export a CRL to a file") }
        },
        "options"  => {
          "caname"     => { "help" => "CA name", "type" => "string" },
          "certname"   => { "help" => "certificat-name", "type" => "string" },
          "cn"         => { "help" => "common name", "type" => "string" },
          "email"      => {
            "help"    => _("E-mail address"),
            "type"    => "string",
            "example" => "my@email.addr"
          },
          "ou"         => {
            "help" => _("Organizational unit"),
            "type" => "string"
          },
          "o"          => { "help" => _("Organization"), "type" => "string" },
          "l"          => { "help" => _("Locality"), "type" => "string" },
          "st"         => { "help" => _("State"), "type" => "string" },
          "c"          => { "help" => _("Country"), "type" => "string" },
          "days"       => { "help" => _("Valid days"), "type" => "string" },
          "keyLength"  => {
            "help"    => _("Key length"),
            "type"    => "string",
            "example" => "2048"
          },
          "keyPasswd"  => {
            "help"    => _(
              "Password (Security: This should be given by an environment variable)"
            ),
            "type"    => "string",
            "example" => "keyPasswd=mypassword yast2 ca-mgm createCA -caname myCA"
          },
          "type"       => { "help" => "client | server", "type" => "string" },
          "type"       => { "help" => "client | server", "type" => "string" },
          "capasswd"   => {
            "help"    => _(
              "CA password (Security: This should be given by an environment variable)"
            ),
            "type"    => "string",
            "example" => "keyPasswd=mypassword capasswd=mycapassword yast2 ca-mgm createCertificate ..."
          },
          "p12passwd"  => {
            "help"    => _(
              "P12 password (Security: This should be given by an environment variable)"
            ),
            "type"    => "string",
            "example" => "p12passwd=myp12password yast2 ca-mgm exportCA..."
          },
          "certFormat" => {
            "help" => "PEM_CERT | PEM_CERT_KEY | PEM_CERT_ENCKEY | DER_CERT | PKCS12 | PKCS12_CHAIN",
            "type" => "string"
          },
          "crlFormat"  => { "help" => "PEM | DER", "type" => "string" },
          "file"       => {
            "help" => _("Path of the exported CA, certificate, or CRL"),
            "type" => "string"
          }
        },
        "mappings" => {
          "createCA"          => [
            "caname",
            "cn",
            "email",
            "ou",
            "o",
            "l",
            "st",
            "c",
            "days",
            "keyLength",
            "keyPasswd"
          ],
          "createCertificate" => [
            "caname",
            "type",
            "cn",
            "email",
            "ou",
            "o",
            "l",
            "st",
            "c",
            "days",
            "keyLength",
            "capasswd",
            "keyPasswd"
          ],
          "createCRL"         => ["caname", "days", "capasswd"],
          "exportCA"          => [
            "caname",
            "certFormat",
            "file",
            "capasswd",
            "p12passwd"
          ],
          "exportCertificate" => [
            "caname",
            "capasswd",
            "certname",
            "certFormat",
            "file",
            "keyPasswd",
            "p12passwd"
          ],
          "exportCRL"         => ["caname", "capasswd", "crlFormat", "file"]
        }
      }



      # The main ()
      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("CaMgm module started")

      Yast.include self, "ca-management/wizards.rb"

      @ret = true

      # Initialize the arguments
      if !CommandLine.Init(@cmdline, WFM.Args)
        Builtins.y2error("Commandline init failed")
        return false
      end

      if CommandLine.StartGUI
        # main ui function
        MainSequence()
      else
        # command line options
        # Init variables
        @command = ""
        @flags = []
        @options = {}
        @exit = ""
        @l = []

        while !CommandLine.Done
          @m = CommandLine.Command
          @command = Ops.get_string(@m, "command", "exit")
          @options = Ops.get_map(@m, "options", {})

          # createCA
          if @command == "createCA"
            @ret = cmdCreateCA(@options)
          # createCertificate
          elsif @command == "createCertificate"
            @ret = cmdCreateCertificate(@options)
          # createCRL
          elsif @command == "createCRL"
            @ret = cmdCreateCRL(@options)
          # exportCA
          elsif @command == "exportCA"
            @ret = cmdExportCAtoFile(@options)
          # exportCertificate
          elsif @command == "exportCertificate"
            @ret = cmdExportCertificateToFile(@options)
          # exportCRL
          elsif @command == "exportCRL"
            @ret = cmdExportCRLtoFile(@options)
          else
            # maybe we got "exit" or "quit"
            if !CommandLine.Done
              CommandLine.Print("Unknown command (should not happen)")
              next
            end
          end
        end
      end

      # Finish
      Builtins.y2milestone("CaMgm module finished")
      Builtins.y2milestone("----------------------------------------")

      @ret 

      # EOF
    end
  end
end

Yast::CaMgmClient.new.main

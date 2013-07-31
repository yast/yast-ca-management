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
# File:        clients/common_cert.ycp
# Package:     CA Management
# Summary:     Main file
# Authors:     Stefan Schubert <schubi@suse.de>
#
# $Id$
#
# Showing current common server certificate
module Yast
  class CommonCertClient < Client
    def main
      Yast.import "UI"

      #**
      # <h3>Common Server Certificate</h3>

      textdomain "ca-management"
      Yast.import "CaMgm"
      Yast.import "CommandLine"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "YaPI::CaManagement"

      Yast.include self, "ca-management/util.rb"

      # The main ()
      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("common_cert module started")

      @cmdline = {
        "id"         => "common_cert",
        "help"       => _("Common Server Certificate"),
        "guihandler" => fun_ref(method(:MainSequence), "symbol ()")
      }
      CommandLine.Run(@cmdline)

      # Finish
      Builtins.y2milestone("common_cert finished")
      Builtins.y2milestone("----------------------------------------") 


      # EOF

      nil
    end

    # Open main dialog sequence
    def MainSequence
      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("common_cert")

      # help text 1/8
      helptext = _(
        "<p>A Server Certificate is used by services which provide SSL/TLS encrypted network connections.</p>"
      )

      # help text 2/8
      helptext = Ops.add(
        helptext,
        _(
          "<p>The purpose of the <b>Common Server Certificate</b> is, to provide a certificate for several services running on this host. "
        )
      )

      # help text 3/8
      helptext = Ops.add(
        helptext,
        _(
          "Some YaST modules provide the capability to use this certificate during configuration of such a service.</p>"
        )
      )

      # help text 4/8
      helptext = Ops.add(
        helptext,
        _(
          "<p>With the <b>Import/Replace</b> button you can add a new server certificate or replace the current one.</p>"
        )
      )

      # help text 5/8
      helptext = Ops.add(
        helptext,
        _(
          "<p>You can remove the Certificates by clicking the <b>Remove</b> button. But make sure, that it is not used anymore by other services.</p>"
        )
      )

      # help text 6/8
      helptext = Ops.add(
        helptext,
        _(
          "<p>Certificates can be written to a file using <b>Export to File</b> in section <b>Certificate</b> in the <b>CA Management</b> module.</p>"
        )
      )

      # help text 7/8
      helptext = Ops.add(
        helptext,
        _(
          "<p>Certificates to import from disk must have been written in <b>PKCS12 format with CA chain</b>.</p>"
        )
      )

      # help text 8/8
      helptext = Ops.add(
        helptext,
        _("<p>For more information, please read the manual.</p>")
      )

      ui = nil
      begin
        ret = Convert.to_string(
          YaPI::CaManagement.ReadFile(
            {
              "inFile"   => "/etc/ssl/servercerts/servercert.pem",
              "datatype" => "CERTIFICATE",
              "inForm"   => "PEM",
              "type"     => "plain"
            }
          )
        )

        Builtins.y2milestone(
          "ReadCertificate(/etc/ssl/servercerts/servercert.pem): %1",
          ret
        )
        if ret == nil
          ret = "<pre>Common Server Certificate not found.\nYou can import a certificate from disk</pre>"
        else
          ret = Ops.add(Ops.add("<pre>", ret), "</pre>")
        end

        contents = VBox(
          Left(Label(_("Description"))),
          VSpacing(0.5),
          RichText(ret),
          VSpacing(0.5),
          HBox(
            HStretch(),
            # push button label
            PushButton(Id(:remove), _("&Remove")),
            # push button label
            PushButton(Id(:importDisk), _("&Import/Replace"))
          )
        )

        # To translators: dialog label
        Wizard.SetContents(
          _("Common Server Certificate"),
          contents,
          helptext,
          false,
          true
        )
        Wizard.SetNextButton(:next, Label.FinishButton)

        ui = Convert.to_symbol(UI.UserInput)
        if ui == :importDisk
          importCertificateFromDisk
          ui = :again
        end
        if ui == :remove
          crt = Convert.to_map(
            YaPI::CaManagement.ReadFile(
              {
                "inFile"   => "/etc/ssl/servercerts/servercert.pem",
                "datatype" => "CERTIFICATE",
                "inForm"   => "PEM",
                "type"     => "parsed"
              }
            )
          )
          expired = Ops.get_integer(crt, "EXPIRED", 0)
          reallyRemove = false
          if expired == 1
            # To translators: popup yes/no question
            reallyRemove = Popup.YesNo("Really remove the Certificate?")
          else
            #removeCertificateFromDisk();
            reallyRemove = Popup.AnyQuestion(
              Label.WarningMsg,
              # To translators: warning popup yes/no question (1/3)
              _("The certificate is not yet expired.\n") +
                # To translators: warning popup yes/no question (2/3)
                _(
                  "Please make sure, that no service use this certificate anymore.\n\n"
                ) +
                # To translators: warning popup yes/no question (3/3)
                _("Are you sure, that you want to remove the certificate?"),
              Label.YesButton,
              Label.NoButton,
              :focus_no
            )
          end
          Builtins.y2milestone("Remove certificate? => %1", reallyRemove)
          YaPI::CaManagement.RemoveCommonServerCertificate if reallyRemove
          ui = :again
        end
        ui = :abort if ui == :cancel
      end until Builtins.contains([:back, :next, :abort], ui)
      Wizard.CloseDialog

      nil
    end
  end
end

Yast::CommonCertClient.new.main

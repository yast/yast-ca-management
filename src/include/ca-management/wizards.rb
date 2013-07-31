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
# File:        include/ca-management/wizards.ycp
# Package:     Configuration of CAs
# Summary:     Wizards definitions
# Authors:     Stefan Schubert <schubi@suse.de>
#
# $Id$
module Yast
  module CaManagementWizardsInclude
    def initialize_ca_management_wizards(include_target)
      Yast.import "UI"
      textdomain "ca-management"

      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.include include_target, "wizard/sequencer.rb"

      Yast.include include_target, "ca-management/popup.rb"
      Yast.include include_target, "ca-management/startup.rb"
      Yast.include include_target, "ca-management/new_cert.rb"
      Yast.include include_target, "ca-management/util.rb"
      Yast.include include_target, "ca-management/new_cert_advanced.rb"
      Yast.include include_target, "ca-management/ca.rb"
      Yast.include include_target, "ca-management/dialog-ca.rb"
    end

    # Creating new Root CA sequence
    # @return sequence result
    def newCASequence
      aliases = {
        "new_certinit"      => lambda { new_cert_init("Root CA") },
        "new_certSaveDef"   => lambda { new_cert_save_default },
        "new_cert1"         => lambda { new_cert1("Root CA") },
        "new_cert2"         => lambda { new_cert2("Root CA") },
        "new_cert3"         => lambda { new_cert3("Root CA") },
        "new_cert_advanced" => lambda { new_cert_advanced(false, "Root CA") }
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(aliases, CaMgm.certificateSequence)

      UI.CloseDialog

      ret
    end


    # Main workflow of the CA management configuration
    # @return sequence result
    def MainSequence
      aliases = {
        "startup"        => lambda { Startup() },
        "new_certCA"     => lambda { newCASequence },
        "new_certServer" => lambda { newServerCertificateSequence },
        "new_certClient" => lambda { newClientCertificateSequence },
        "ca_main"        => lambda { runCADialog }
      }

      sequence = {
        "ws_start"       => "startup",
        "startup"        => {
          :next       => :abort,
          :createRoot => "new_certCA",
          :enter      => "ca_main",
          :import     => "startup",
          :delete     => "startup"
        },
        "new_certCA"     => { :next => "startup", :abort => "startup" },
        "ca_main"        => {
          :back  => "startup",
          :next  => "startup",
          :abort => "startup"
        },
        "new_certServer" =>
          #				`next       	: "certificate",
          #				`abort		: "certificate",
          {},
        "new_certClient" =>
          #				`next       	: "certificate",
          #				`abort		: "certificate",
          {}
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(aliases, sequence)

      UI.CloseDialog

      ret
    end
  end
end

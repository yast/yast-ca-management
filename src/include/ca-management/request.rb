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
  module CaManagementRequestInclude
    def initialize_ca_management_request(include_target)
      Yast.import "CaMgm"
      Yast.import "Wizard"
      Yast.import "Label"
      Yast.import "Popup"

      textdomain "ca-management"

      Yast.include include_target, "ca-management/signRequest.rb"

      @requestID = []

      # help text 1/6
      @requestHelptext = _(
        "<p>First, see a list view with all available requests of this CA. The columns are the DN of the request including the e-mail address.</p>"
      )
      # help text 2/6
      @requestHelptext = Ops.add(
        @requestHelptext,
        _("<p>Select one of the requests and execute some actions.</p>")
      )
      # help text 3/6
      @requestHelptext = Ops.add(
        @requestHelptext,
        _(
          "<p><b>View</b> opens a window with a text representation of the complete request.</p>"
        )
      )
      # help text 4/6
      @requestHelptext = Ops.add(
        @requestHelptext,
        _(
          "<p>You can also <b>Sign</b>, <b>Delete</b>, or <b>Export</b> a request.</p>"
        )
      )
      # help text 5/6
      @requestHelptext = Ops.add(
        @requestHelptext,
        _(
          "<p>With <b>Import</b>, read a new request. With <b>Add</b>, generate a new request.</p>"
        )
      )
      # help text 6/6
      @requestHelptext = Ops.add(
        @requestHelptext,
        _(
          "<p>In the area below, see the most important values of the selected request.</p>"
        )
      )
    end

    # Creating new Client Request sequence
    # @return sequence result
    def newClientRequestSequence
      aliases = {
        "new_certinit"      => lambda { new_cert_init("Client Request") },
        "new_certSaveDef"   => lambda { new_cert_save_default },
        "new_cert1"         => lambda { new_cert1("Client Request") },
        "new_cert2"         => lambda { new_cert2("Client Request") },
        "new_cert3"         => lambda { new_cert3("Client Request") },
        "new_cert_advanced" => lambda do
          new_cert_advanced(false, "Client Request")
        end
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(aliases, CaMgm.certificateSequence)

      UI.CloseDialog

      ret
    end

    # Creating new Server Request sequence
    # @return sequence result
    def newServerRequestSequence
      aliases = {
        "new_certinit"      => lambda { new_cert_init("Server Request") },
        "new_certSaveDef"   => lambda { new_cert_save_default },
        "new_cert1"         => lambda { new_cert1("Server Request") },
        "new_cert2"         => lambda { new_cert2("Server Request") },
        "new_cert3"         => lambda { new_cert3("Server Request") },
        "new_cert_advanced" => lambda do
          new_cert_advanced(false, "Server Request")
        end
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(aliases, CaMgm.certificateSequence)

      UI.CloseDialog

      ret
    end

    # Creating new CA Request sequence
    # @return sequence result
    def newCARequestSequence
      aliases = {
        "new_certinit"      => lambda { new_cert_init("Sub CA Request") },
        "new_certSaveDef"   => lambda { new_cert_save_default },
        "new_cert1"         => lambda { new_cert1("Sub CA Request") },
        "new_cert2"         => lambda { new_cert2("Sub CA Request") },
        "new_cert3"         => lambda { new_cert3("Sub CA Request") },
        "new_cert_advanced" => lambda do
          new_cert_advanced(false, "Sub-CA Request")
        end
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(aliases, CaMgm.certificateSequence)

      UI.CloseDialog

      ret
    end


    # Signing new Request sequence
    # @param [Object] kind (`signClient,`signServer,`signCA)
    # @return sequence result
    def signRequestSequence(kind)
      kind = deep_copy(kind)
      aliases = {
        :signClient => {
          "req_init"     => lambda { signRequestInit("Client Request") },
          "req_sign1"    => lambda { signRequest1("Client Request") },
          "req_sign2"    => lambda { signRequest2("Client Request") },
          "req_advanced" => lambda { new_cert_advanced(false, "Sign Request") }
        },
        :signServer => {
          "req_init"     => lambda { signRequestInit("Server Request") },
          "req_sign1"    => lambda { signRequest1("Server Request") },
          "req_sign2"    => lambda { signRequest2("Server Request") },
          "req_advanced" => lambda { new_cert_advanced(false, "Sign Request") }
        },
        :signCA     => {
          "req_init"     => lambda { signRequestInit("CA Request") },
          "req_sign1"    => lambda { signRequest1("CA Request") },
          "req_sign2"    => lambda { signRequest2("CA Request") },
          "req_advanced" => lambda { new_cert_advanced(false, "Sign Request") }
        }
      }


      requestSequence = {
        "ws_start"     => "req_init",
        "req_init"     => { :next => "req_sign1", :abort => :abort },
        "req_sign1"    => {
          :next  => "req_sign2",
          :again => "req_sign1",
          :abort => :abort
        },
        "req_sign2"    => {
          :abort => :abort,
          :next  => :abort,
          :again => "req_sign2",
          :back  => "req_sign1",
          :edit  => "req_advanced"
        },
        "req_advanced" => { :abort => :abort, :back => "req_sign2" }
      }

      Wizard.CreateDialog
      Wizard.SetDesktopTitleAndIcon("ca_mgm")
      ret = WizardSequencer(Ops.get_map(aliases, kind, {}), requestSequence)

      UI.CloseDialog

      ret
    end



    # showLongRequestDescription - description of a request in textform
    # @param CA name , certification name
    def showLongRequestDescription(_CAname, _Request)
      ret = Convert.to_string(
        YaPI::CaManagement.ReadRequest(
          {
            "caName"   => _CAname,
            "caPasswd" => getPassword(_CAname),
            "request"  => _Request,
            "type"     => "plain"
          }
        )
      )

      Builtins.y2milestone("ReadRequest(%1,%2): %3", _CAname, _Request, ret)
      ret = Ops.add(Ops.add("<pre>", ret), "</pre>")

      if ret == nil
        showErrorCaManagement
      else
        UI.OpenDialog(
          Opt(:decorated),
          HBox(
            VSpacing(16),
            VBox(
              HSpacing(100),
              # popup window header
              Heading(_("Description")),
              VSpacing(0.5),
              RichText(ret),
              VSpacing(1.5),
              # push button label
              PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton)
            )
          )
        )

        UI.SetFocus(Id(:ok))
        UI.UserInput
        UI.CloseDialog
      end

      nil
    end

    # Creates request items
    #
    # @param name of the selected request
    # @return a list request items formated for a UI table
    def getRequestList(currentCA)
      result = []
      i = 0

      @requestID = []

      ret = Convert.convert(
        YaPI::CaManagement.ReadRequestList(
          { "caName" => currentCA, "caPasswd" => getPassword(currentCA) }
        ),
        :from => "list",
        :to   => "list <map>"
      )
      if ret == nil
        showErrorCaManagement
        return nil
      end
      Builtins.y2milestone("ReadRequestList(%1): %2", currentCA, ret)


      Builtins.foreach(ret) do |element|
        result = Builtins.add(
          result,
          Item(
            Id(i),
            Ops.get_string(element, "commonName", ""),
            Ops.get_string(element, "emailAddress", ""),
            Ops.get_string(element, "organizationName", ""),
            Ops.get_string(element, "organizationalUnitName", ""),
            Ops.get_string(element, "localityName", ""),
            Ops.get_string(element, "stateOrProvinceName", ""),
            Ops.get_string(element, "country", ""),
            Ops.get_string(element, "date", "")
          )
        )
        @requestID = Builtins.add(
          @requestID,
          Ops.get_string(element, "request", "")
        )
        i = Ops.add(i, 1)
      end
      deep_copy(result)
    end

    # Dialog Tab - request -
    # @return [Yast::Term] for requests of a selected CA
    def getRequestTab
      certTermList = getRequestList(CaMgm.currentCA)
      return nil if certTermList == nil

      contents = VBox(
        VSpacing(1),
        HBox(
          HSpacing(1),
          Table(
            Id(:table),
            Opt(:notify, :immediate),
            Header(
              # To translators: table headers
              _("Common Name"),
              _("E-Mail Address"),
              _("Organization"),
              _("Organizational Unit"),
              _("Locality"),
              _("State"),
              _("Country"),
              _("Generate Time")
            ),
            certTermList
          ),
          HSpacing(1)
        ),
        HBox(HSpacing(1), RichText(Id(:textinfo), ""), HSpacing(1)),
        HBox(
          HSpacing(1),
          PushButton(Id(:import), _("&Import")),
          HSpacing(1),
          MenuButton(
            _("Add"),
            [
              Item(Id(:addCARequest), _("Add Sub-CA Request")),
              Item(Id(:addServerRequest), _("Add Server Request")),
              Item(Id(:addClientRequest), _("Add Client Request"))
            ]
          ),
          HStretch(),
          MenuButton(
            Id(:request),
            _("&Request"),
            [
              Item(Id(:view), _("&View")),
              Item(Id(:reqcpw), _("&Change Password")),
              term(
                :menu,
                _("Sign"),
                [
                  Item(Id(:signClient), _("As Client Certificate")),
                  Item(Id(:signServer), _("As Server Certificate")),
                  Item(Id(:signCA), _("As CA Certificate"))
                ]
              ),
              Item(Id(:delete), _("&Delete")),
              Item(Id(:exportFile), _("Export to File"))
            ]
          ),
          HSpacing(1)
        ),
        VSpacing(1)
      )
      deep_copy(contents)
    end

    # Initialize the tab of the dialog
    def initRequestTab
      anyitems = UI.QueryWidget(Id(:table), :CurrentItem) != nil
      UI.ChangeWidget(Id(:request), :Enabled, anyitems)

      id = Convert.to_integer(UI.QueryWidget(Id(:table), :CurrentItem))
      CaMgm.currentRequest = Ops.get(@requestID, id, "")

      if anyitems
        ret = Convert.to_map(
          YaPI::CaManagement.ReadRequest(
            {
              "caName"   => CaMgm.currentCA,
              "caPasswd" => getPassword(CaMgm.currentCA),
              "request"  => CaMgm.currentRequest,
              "type"     => "parsed"
            }
          )
        )
        Builtins.y2milestone(
          "ReadRequest(%1,%2): %3",
          CaMgm.currentCA,
          CaMgm.currentRequest,
          ret
        )

        # Add generation time to map
        itemTerm = Convert.to_term(UI.QueryWidget(Id(:table), term(:Item, id)))
        ret = Builtins.add(ret, "date", Ops.get_string(itemTerm, 8, ""))

        UI.ChangeWidget(
          Id(:textinfo),
          :Value,
          getRequestDescription(ret, false)
        )
      end

      nil
    end


    # Handle events in a tab of a dialog
    def handleRequestTab(event)
      event = deep_copy(event)
      ui = Ops.get(event, "ID")

      initRequestTab if ui == :table

      if ui == :view
        showLongRequestDescription(CaMgm.currentCA, CaMgm.currentRequest)
      end
      if ui == :reqcpw
        # we need to fake a certificate name
        changePassword(CaMgm.currentCA, Ops.add("00:", CaMgm.currentRequest))
      end
      if ui == :delete
        if Popup.ContinueCancelHeadline(
            _("Delete"),
            _("Delete current request?")
          )
          ret = nil
          ret = YaPI::CaManagement.DeleteRequest(
            {
              "caName"   => CaMgm.currentCA,
              "request"  => CaMgm.currentRequest,
              "caPasswd" => getPassword(CaMgm.currentCA)
            }
          )
          Builtins.y2milestone(
            "DeleteRequest(%1) return %2",
            { "caName" => CaMgm.currentCA, "request" => CaMgm.currentRequest },
            ret
          )
          showErrorCaManagement if ret == nil || ret == false
          ui = :again
        end
      end
      if ui == :signServer || ui == :signClient || ui == :signCA
        signRequestSequence(ui)
        ui = :again
      end
      if ui == :exportFile
        #Popup::Error(_("Currently not supported."));
        newreqfile = UI.AskForSaveFileName("/root", "*", _("Save as"))
        if newreqfile != nil && newreqfile != ""
          ret = Convert.to_string(
            YaPI::CaManagement.ExportRequest(
              {
                "caName"          => CaMgm.currentCA,
                "caPasswd"        => getPassword(CaMgm.currentCA),
                "request"         => CaMgm.currentRequest,
                "destinationFile" => newreqfile
              }
            )
          )
          if ret != nil && ret == "1"
            Popup.Message(_("Saved to file successfully."))
          else
            showErrorCaManagement
          end
        end
      end
      if ui == :import
        importRequestFromDisk(CaMgm.currentCA)
        ui = :again
      end
      if ui == :addCARequest
        newCARequestSequence
        ui = :again
      end
      if ui == :addServerRequest
        newServerRequestSequence
        ui = :again
      end
      if ui == :addClientRequest
        newClientRequestSequence
        ui = :again
      end

      Convert.to_symbol(ui)
    end
  end
end
